/**
 * The sandbox signing path end-to-end (Item 0, increment 3): a REAL root daemon
 * process + the client, over a real unix socket — the mechanism that replaces
 * sudo under `no_new_privs`. Privilege separation itself (root daemon vs pluto
 * client) is verified live on the box; this proves the socket protocol,
 * readiness, DB-derived signing, and refusal all work.
 */
import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { openStateDb } from "./db.js";
import { createFindingsRepo } from "./findings-repo.js";
import { type PromotionClaim, verifyPromotion } from "./promotion.js";
import { resolveSigner } from "./promotion-signer.js";
import { createTargetsRepo } from "./targets-repo.js";
import { createValidationsRepo } from "./validations-repo.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const DAEMON = fileURLToPath(new URL("./promotion-sign-daemon.js", import.meta.url));
const CLIENT = fileURLToPath(new URL("./promotion-sign-client.js", import.meta.url));

async function waitForSocket(path: string, ms = 5000): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (existsSync(path)) return;
		await sleep(25);
	}
	throw new Error(`daemon socket ${path} did not appear within ${ms}ms`);
}

test("sign via the real daemon+client over a unix socket; refuse a failing validation", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sock-"));
	const keyFile = join(dir, "promotion_ed25519.key");
	writeFileSync(keyFile, privPem);
	const sock = join(dir, "sign.sock");

	const saved = {
		state: process.env["PLUTO_STATE_DIR"],
		key: process.env["PLUTO_PROMOTION_PRIVKEY"],
		cmd: process.env["PLUTO_PROMOTION_SIGNER_CMD"],
	};
	process.env["PLUTO_STATE_DIR"] = join(dir, "state");
	process.env["PLUTO_PROMOTION_PRIVKEY"] = keyFile;
	process.env["PLUTO_PROMOTION_SIGNER_CMD"] = `${process.execPath} ${CLIENT} ${sock}`;

	let daemon: ChildProcess | undefined;
	try {
		daemon = spawn(process.execPath, [DAEMON, sock], { stdio: "ignore" });
		await waitForSocket(sock);

		const db = openStateDb(dir);
		const targets = createTargetsRepo(db);
		const validations = createValidationsRepo(db);
		const findings = createFindingsRepo(db, { signer: resolveSigner() });
		const target = targets.create({ label: "sock" });

		// Legit promotion: signed by the daemon, verifies against the public key.
		const finding = findings.create({ targetId: target.id, service: "http" });
		const validation = validations.create({
			findingId: finding.id,
			validator: "sqli",
			baselineRef: "evidence/b.json",
			diffSummary: "diff",
			passed: true,
		});
		const promoted = findings.promote(finding.id, validation.id);
		assert.equal(promoted.status, "validated");
		const row = findings.getPromotion(finding.id);
		assert.ok(row?.signature, "the daemon must have signed the promotion");
		const claim: PromotionClaim = {
			findingId: row.finding_id,
			validationId: row.validation_id,
			validator: row.validator,
			targetId: row.target_id,
			evidenceRef: row.evidence_ref,
		};
		assert.equal(verifyPromotion(claim, row.signature, publicKey), true);

		// The daemon (root gate) refuses a claim for a failing validation even when
		// the in-realm caller bypasses promote()'s own check.
		const f2 = findings.create({ targetId: target.id, service: "http" });
		const failing = validations.create({ findingId: f2.id, validator: "sqli", diffSummary: "none", passed: false });
		const signer = resolveSigner();
		assert.ok(signer);
		assert.throws(
			() => signer({ findingId: f2.id, validationId: failing.id, validator: "sqli", targetId: target.id, evidenceRef: "x" }),
			/did not pass|refusing to sign|exited/i,
		);
		db.close();
	} finally {
		daemon?.kill("SIGTERM");
		for (const [k, v] of [
			["PLUTO_STATE_DIR", saved.state],
			["PLUTO_PROMOTION_PRIVKEY", saved.key],
			["PLUTO_PROMOTION_SIGNER_CMD", saved.cmd],
		] as const) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
	}
});
