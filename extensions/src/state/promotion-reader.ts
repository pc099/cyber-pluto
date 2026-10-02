#!/usr/bin/env node
/** Fixed read-only SQLite worker. Production runs inside the wrapper as pluto;
 * it never receives keys, provider credentials, caller SQL or caller paths. */
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { derivePromotionClaim } from "./promotion-sign-core.js";
import { SIGNER_MAX_BYTES } from "./signer-health.js";

export function assertPromotionReaderSchema(db: DatabaseSync): void {
	for (const name of ["findings", "validations"]) {
		const row = db.prepare("SELECT type, substr(sql,1,128) AS declaration FROM sqlite_schema WHERE name=?").get(name);
		if (row?.type !== "table" || typeof row.declaration !== "string" || !/^CREATE\s+TABLE\s+/i.test(row.declaration)) throw new Error("Reader requires ordinary findings/validations tables");
	}
}

export function runPromotionReader(): void {
	const uid = Number(process.env.PLUTO_READINESS_UID);
	if (process.env.PLUTO_SANDBOX_MODE !== "requested" || !Number.isSafeInteger(uid) || uid <= 0 || process.getuid?.() !== uid) throw new Error("Reader requires the confined unprivileged identity");
	if (!/^NoNewPrivs:\s+1$/m.test(readFileSync("/proc/self/status", "utf8"))) throw new Error("Reader requires no_new_privs");
	for (const name of Object.keys(process.env)) if (name === "PLUTO_PROMOTION_PRIVKEY" || /(?:API_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN)$/.test(name)) throw new Error("Reader refuses credential environment");
	const state = process.env.PLUTO_STATE_DIR;
	if (!state || !isAbsolute(state)) throw new Error("Reader requires fixed absolute state path");
	const ledger = join(state, "pluto.db");
	if (realpathSync(ledger) !== ledger) throw new Error("Reader requires canonical ledger");
	const pinned = new Map<string, string>();
	for (let path = ledger; ; path = dirname(path)) {
		const info = lstatSync(path);
		if (info.isSymbolicLink()) throw new Error("Reader refuses substituted ledger ancestry");
		pinned.set(path, `${info.dev}:${info.ino}`);
		if (dirname(path) === path) break;
	}
	const assertLedger = (): void => {
		for (const [path, expected] of pinned) {
			const info = lstatSync(path);
			if (info.isSymbolicLink() || `${info.dev}:${info.ino}` !== expected) throw new Error("Reader ledger ancestry replaced");
		}
		const info = lstatSync(ledger);
		if (!info.isFile() || info.nlink !== 1 || info.uid !== uid) throw new Error("Reader ledger ownership/type mismatch");
		for (const suffix of ["-wal", "-shm", "-journal"]) {
			try {
				const side = lstatSync(`${ledger}${suffix}`);
				if (!side.isFile() || side.isSymbolicLink() || side.nlink !== 1 || side.uid !== uid) throw new Error("Reader refuses unsafe sidecar");
			} catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
		}
	};
	assertLedger();
	const db = new DatabaseSync(ledger, { readOnly: true });
	const ready = (): { ledgerIdentity: string; uid: number; noNewPrivileges: true } => {
		assertLedger();
		assertPromotionReaderSchema(db);
		db.prepare("SELECT id FROM findings LIMIT 1").get();
		db.prepare("SELECT id FROM validations LIMIT 1").get();
		assertLedger();
		return { ledgerIdentity: pinned.get(ledger)!, uid, noNewPrivileges: true };
	};
	try { ready(); } catch (error) { db.close(); throw error; }
	let buffered = Buffer.alloc(0);
	let closed = false;
	const close = (): void => { if (!closed) { closed = true; db.close(); } };
	process.on("SIGTERM", () => { close(); process.exit(0); });
	process.on("SIGINT", () => { close(); process.exit(0); });
	process.stdin.on("end", () => { close(); process.exit(0); });
	process.stdin.on("error", () => { close(); process.exit(1); });
	process.stdin.on("data", (chunk: Buffer) => {
		buffered = Buffer.concat([buffered, chunk]);
		if (buffered.length > SIGNER_MAX_BYTES) { close(); process.exit(1); }
		let boundary: number;
		while ((boundary = buffered.indexOf(10)) >= 0) {
			const frame = buffered.subarray(0, boundary).toString("utf8"); buffered = buffered.subarray(boundary + 1);
			let seq: number | undefined;
			let reply: unknown;
			try {
				const input = JSON.parse(frame) as { seq?: unknown; op?: unknown; findingId?: unknown; validationId?: unknown };
				if (!input || Array.isArray(input) || !Number.isSafeInteger(input.seq) || Number(input.seq) <= 0) throw new Error("Invalid reader correlation");
				seq = Number(input.seq);
				if (input.op === "ready" && Object.keys(input).length === 2) reply = { seq, ok: true, ready: ready() };
				else if (input.op === "claim" && Object.keys(input).length === 4 && Number.isSafeInteger(input.findingId) && Number(input.findingId) > 0 && Number.isSafeInteger(input.validationId) && Number(input.validationId) > 0) {
					assertLedger();
					assertPromotionReaderSchema(db);
					const claim = derivePromotionClaim(db, JSON.stringify({ findingId: input.findingId, validationId: input.validationId }));
					assertLedger(); reply = { seq, ok: true, claim };
				} else throw new Error("Unknown or invalid fixed reader operation");
			} catch (error) {
				if (seq === undefined) { close(); process.exit(1); }
				reply = { seq, ok: false, error: error instanceof Error ? error.message.slice(0, 512) : "reader refused" };
			}
			const text = JSON.stringify(reply);
			if (Buffer.byteLength(text) > SIGNER_MAX_BYTES) { close(); process.exit(1); }
			process.stdout.write(`${text}\n`);
		}
	});
}

if (process.argv[1]?.endsWith("/state/promotion-reader.js")) {
	try { runPromotionReader(); }
	catch (error) { process.stderr.write(`promotion-reader: ${error instanceof Error ? error.message.slice(0, 512) : "startup failure"}\n`); process.exitCode = 1; }
}
