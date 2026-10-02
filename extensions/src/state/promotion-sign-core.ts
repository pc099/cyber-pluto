/** Root-held signing authority. Writable validation rows remain forgeable;
 * signatures establish signer provenance, not independent evidence truth. */
import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { closeSync, constants, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { type PromotionClaim, signPromotion } from "./promotion.js";
import { canonicalHealth, publicKeyFingerprint, type SignerHealthClaim } from "./signer-health.js";
import type { FindingRow, ValidationRow } from "./types.js";

function identity(path: string): string {
	const st = lstatSync(path);
	if (st.isSymbolicLink()) throw new Error(`signer refuses symlink: ${path}`);
	return `${st.dev}:${st.ino}`;
}
/** Root-owned parents, with a sticky root directory permitted for private test roots. */
export function assertProtectedRootParents(path: string): void {
	if (!isAbsolute(path)) throw new Error("protected signer path must be absolute");
	for (let p = dirname(path); ; p = dirname(p)) {
		const st = lstatSync(p);
		if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== 0 || ((st.mode & 0o022) !== 0 && (st.mode & 0o1000) === 0)) {
			throw new Error(`unsafe root-controlled signer parent: ${p}`);
		}
		if (dirname(p) === p) break;
	}
}
function rootKey(path: string, privateKey: boolean): KeyObject {
	assertProtectedRootParents(path);
	const st = lstatSync(path);
	if (!st.isFile() || st.isSymbolicLink() || st.uid !== 0 || (st.mode & (privateKey ? 0o077 : 0o022)) !== 0) {
		throw new Error("unsafe root signing/verifying key ownership or permissions");
	}
	return privateKey ? createPrivateKey(readFileSync(path)) : createPublicKey(readFileSync(path));
}
export function derivePromotionClaim(db: DatabaseSync, rawJson: string): PromotionClaim {
	let input: unknown;
	try { input = JSON.parse(rawJson); } catch { throw new Error("claim is not valid JSON"); }
	if (!input || typeof input !== "object") throw new Error("invalid promotion claim");
	const supplied = input as Partial<PromotionClaim>;
	if (!Number.isSafeInteger(supplied.findingId) || !Number.isSafeInteger(supplied.validationId)) throw new Error("claim must contain integer findingId and validationId");
	const fid = supplied.findingId as number; const vid = supplied.validationId as number;
	const finding = db.prepare("SELECT id, target_id, status FROM findings WHERE id = ?").get(fid) as unknown as FindingRow | undefined;
	if (!finding) throw new Error(`finding ${fid} does not exist`);
	if (finding.status !== "candidate") throw new Error(`finding ${fid} is '${finding.status}', not 'candidate' — refusing to sign`);
	// Do not copy unrelated or unbounded attacker-writable row text into root's
	// JS heap. The extra character detects oversized signing fields.
	const validation = db.prepare("SELECT id, finding_id, passed, substr(validator,1,129) AS validator, substr(baseline_ref,1,4097) AS baseline_ref, substr(attack_ref,1,4097) AS attack_ref FROM validations WHERE id = ?").get(vid) as unknown as ValidationRow | undefined;
	if (!validation) throw new Error(`validation ${vid} does not exist`);
	if (validation.finding_id !== fid) throw new Error(`validation ${vid} belongs to another finding`);
	if (validation.passed !== 1) throw new Error(`validation ${vid} did not pass — refusing to sign`);
	if (typeof validation.validator !== "string" || validation.validator.length > 128 ||
		[validation.baseline_ref, validation.attack_ref].some(ref => ref !== null && (typeof ref !== "string" || ref.length > 4096))) {
		throw new Error("signing fields exceed permitted size or type");
	}
	return { findingId: fid, validationId: vid, validator: validation.validator, targetId: finding.target_id,
		evidenceRef: validation.baseline_ref ?? validation.attack_ref ?? "" };
}
export interface PromotionAuthority {
	ledgerPath: string;
	assertLedger(): void;
	sign(rawJson: string): string;
	health(challenge: string): { claim: SignerHealthClaim; signature: string };
	stop(): void;
	close(): void;
}
export interface SigningContext {
	ledgerPath: string;
	assertLedger(): void;
	signClaim(claim: PromotionClaim): string;
	health(challenge: string): { claim: SignerHealthClaim; signature: string };
	stop(): void;
}
/** Root key/control and pathname identities only. Never opens SQLite. */
export function createSigningContext(env: NodeJS.ProcessEnv = process.env): SigningContext {
	const strict = env.PLUTO_SIGNER_STRICT === "1";
	const cwd = env.PLUTO_CWD ?? process.cwd();
	const ledgerPath = resolve(cwd, env.PLUTO_STATE_DIR ?? "state", "pluto.db");
	const keyPath = env.PLUTO_PROMOTION_PRIVKEY;
	if (!keyPath) throw new Error("PLUTO_PROMOTION_PRIVKEY is not set");
	if (strict && (process.getuid?.() !== 0 || !env.PLUTO_STATE_DIR || !isAbsolute(env.PLUTO_STATE_DIR) || !isAbsolute(cwd) ||
		!env.PLUTO_SIGNER_RUN_ID || !/^[A-Za-z0-9-]{1,128}$/.test(env.PLUTO_SIGNER_RUN_ID))) throw new Error("strict signer requires root, absolute ledger and explicit launch identity");
	const key = strict ? rootKey(keyPath, true) : createPrivateKey(readFileSync(keyPath));
	if (key.asymmetricKeyType !== "ed25519") throw new Error("signer key must be ed25519");
	const publicKey = createPublicKey(key);
	if (strict) {
		if (!env.PLUTO_PROMOTION_PUBKEY) throw new Error("strict signer requires public verifying key");
		const configured = rootKey(env.PLUTO_PROMOTION_PUBKEY, false);
		if (publicKeyFingerprint(configured) !== publicKeyFingerprint(publicKey)) throw new Error("signer private/public keys do not match");
	}
	const paths = new Map<string, string>();
	let ledgerOwner: number | undefined;
	if (strict) {
		if (realpathSync(ledgerPath) !== ledgerPath || !lstatSync(ledgerPath).isFile()) throw new Error("signer ledger must be canonical regular file");
		ledgerOwner = lstatSync(ledgerPath).uid;
		for (let p = ledgerPath; ; p = dirname(p)) { paths.set(p, identity(p)); if (dirname(p) === p) break; }
	}
	const assertLedger = (): void => {
		for (const [path, pinned] of paths) {
			if (identity(path) !== pinned) throw new Error("signer ledger or ancestor was replaced");
		}
		if (strict) for (const suffix of ["-wal", "-shm", "-journal"]) {
			try {
				const sidecar = lstatSync(`${ledgerPath}${suffix}`);
				if (!sidecar.isFile() || sidecar.isSymbolicLink() || sidecar.nlink !== 1 || sidecar.uid !== ledgerOwner) throw new Error("unsafe signer ledger sidecar");
			} catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
		}
	};
	assertLedger(); // refuse unsafe sidecars before SQLite opens any path
	return {
		ledgerPath, assertLedger,
		signClaim(claim) { assertLedger(); return signPromotion(claim, key); },
		health(challenge) {
			if (!strict || !/^[a-f0-9]{64}$/.test(challenge)) throw new Error("invalid strict health challenge");
			assertLedger();
			const claim: SignerHealthClaim = { schema: 1, ledgerPath, runId: env.PLUTO_SIGNER_RUN_ID!, challenge,
				keyFingerprint: publicKeyFingerprint(publicKey), databaseIdentity: paths.get(ledgerPath)! };
			return { claim, signature: sign(null, Buffer.from(canonicalHealth(claim)), key).toString("base64") };
		},
		stop() {
			if (!strict || !env.PLUTO_KILL_FILE || !isAbsolute(env.PLUTO_KILL_FILE)) throw new Error("strict operator stop is not configured");
			const path = env.PLUTO_KILL_FILE;
			assertProtectedRootParents(path);
			let fd: number;
			try { fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644); }
			catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
				const st = lstatSync(path);
				if (!st.isFile() || st.isSymbolicLink() || st.uid !== 0 || (st.mode & 0o022) !== 0) throw new Error("unsafe existing operator stop sentinel");
				return;
			}
			try { writeFileSync(fd, `signer operator stop ${new Date().toISOString()}\n`); fsyncSync(fd); } finally { closeSync(fd); }
			const parentFd = openSync(dirname(path), "r"); try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
		},
	};
}
/** Compatibility for trusted local fixtures only. Requested sandbox must use
 * the isolated authority: a read-only root SQLite connection can write SHM. */
export function createPromotionAuthority(env: NodeJS.ProcessEnv = process.env): PromotionAuthority {
	if (env.PLUTO_SANDBOX_MODE === "requested") throw new Error("Requested sandbox requires the confined signing reader; root SQLite is refused");
	const context = createSigningContext(env);
	const db = new DatabaseSync(context.ledgerPath, { readOnly: true });
	try { context.assertLedger(); db.prepare("SELECT id FROM findings LIMIT 1").get(); db.prepare("SELECT id FROM validations LIMIT 1").get(); }
	catch (error) { db.close(); throw error; }
	return {
		ledgerPath: context.ledgerPath, assertLedger: context.assertLedger, health: context.health, stop: context.stop,
		sign(rawJson) { context.assertLedger(); const claim = derivePromotionClaim(db, rawJson); context.assertLedger(); return context.signClaim(claim); },
		close() { db.close(); },
	};
}
/** Legacy trusted one-shot entry point; honors the supplied environment. */
export function signClaimAsRoot(rawJson: string, env: NodeJS.ProcessEnv = process.env): string {
	const authority = createPromotionAuthority(env);
	try { return authority.sign(rawJson); } finally { authority.close(); }
}
