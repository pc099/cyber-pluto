/**
 * Gate-1 forge SENTINEL (Decision 0002, ratified first increment; QA's red-team
 * acceptance test). It measures the residual Item 0 left open, as a standing,
 * committed assertion — converting "we think it's residual" into a fact that CI
 * watches.
 *
 * Two scenarios, both run against a REAL signing daemon + verifier (as the
 * sandbox uses):
 *
 *   1. REGRESSION GUARD (Item 0, must stay closed): the direct status-flip
 *      (`UPDATE findings SET status='validated'` with no signed promotion) is
 *      untrusted and NOT submittable.
 *
 *   2. THE OPEN RESIDUAL (must currently SUCCEED — this is the sentinel): a
 *      hijacked-agent forge of a `passed` validations row (no real validator
 *      ran) yields a GENUINELY signed promotion, because the daemon re-checks
 *      only the pluto-writable row. So it reaches a trusted, submittable
 *      `validated`.
 *
 *   >>> WHEN SCENARIO 2 STARTS FAILING, THE FORGE HAS BEEN CLOSED for this
 *   >>> class (a privileged re-validation / capture-proxy fix landed). At that
 *   >>> point FLIP its assertions to expect refusal, and only THEN may Gate 1 be
 *   >>> called tamper-PROOF (QA's hard NO-GO until this flips). Until then Gate 1
 *   >>> is tamper-EVIDENT only.
 */
import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import type { DatabaseSync } from "node:sqlite";
import { openStateDb } from "./db.js";
import { IllegalStatusTransition, type FindingsRepo, createFindingsRepo } from "./findings-repo.js";
import { resolveSigner } from "./promotion-signer.js";
import { resolveVerifier } from "./promotion-verifier.js";
import { createTargetsRepo } from "./targets-repo.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const DAEMON = fileURLToPath(new URL("./promotion-sign-daemon.js", import.meta.url));
const CLIENT = fileURLToPath(new URL("./promotion-sign-client.js", import.meta.url));

let daemon: ChildProcess | undefined;
let db: DatabaseSync;
let findings: FindingsRepo;
let targetId: number;
const saved: Record<string, string | undefined> = {};

async function waitForSocket(path: string, ms = 5000): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (existsSync(path)) return;
		await sleep(25);
	}
	throw new Error(`daemon socket ${path} did not appear`);
}

before(async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-forge-"));
	const keyFile = join(dir, "priv.key");
	const pubFile = join(dir, "pub.key");
	writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }) as string);
	writeFileSync(pubFile, publicKey.export({ type: "spki", format: "pem" }) as string);
	const sock = join(dir, "sign.sock");

	for (const k of ["PLUTO_STATE_DIR", "PLUTO_PROMOTION_PRIVKEY", "PLUTO_PROMOTION_PUBKEY", "PLUTO_PROMOTION_SIGNER_CMD"]) {
		saved[k] = process.env[k];
	}
	process.env["PLUTO_STATE_DIR"] = join(dir, "state");
	process.env["PLUTO_PROMOTION_PRIVKEY"] = keyFile; // daemon (root) side
	process.env["PLUTO_PROMOTION_PUBKEY"] = pubFile; // verifier (consumer) side
	process.env["PLUTO_PROMOTION_SIGNER_CMD"] = `${process.execPath} ${CLIENT} ${sock}`;

	daemon = spawn(process.execPath, [DAEMON, sock], { stdio: "ignore", env: { ...process.env } });
	await waitForSocket(sock);

	db = openStateDb(dir);
	findings = createFindingsRepo(db, { signer: resolveSigner(), verifier: resolveVerifier() });
	targetId = createTargetsRepo(db).create({ label: "forge" }).id;
});

after(() => {
	daemon?.kill("SIGTERM");
	try {
		db?.close();
	} catch {
		/* ignore */
	}
	for (const [k, v] of Object.entries(saved)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
});

test("REGRESSION (Item 0): the direct status-flip forge stays untrusted and unsubmittable", () => {
	const f = findings.create({ targetId, service: "http" });
	// The exact Item-0 attack: flip status with no signed promotion.
	db.prepare("UPDATE findings SET status = 'validated' WHERE id = ?").run(f.id);
	assert.equal(findings.getById(f.id)?.status, "validated");
	assert.equal(findings.isValidatedTrustworthy(f.id), false, "direct flip must remain untrusted");
	assert.throws(() => findings.markSubmitted(f.id), IllegalStatusTransition, "direct flip must remain unsubmittable");
});

test("SENTINEL (OPEN residual): a forged 'passed' validations row reaches a signed, submittable 'validated'", () => {
	const f = findings.create({ targetId, service: "http" });

	// THE FORGE: a hijacked agent writes a passed validations row directly — no
	// real validator ran — and self-consistent (fake) evidence refs. The
	// validations table is pluto-writable, so this INSERT is exactly what a
	// compromised agent can do.
	const forged = db
		.prepare(
			"INSERT INTO validations (finding_id, validator, baseline_ref, attack_ref, diff_summary, passed) VALUES (?, 'sqli', 'evidence/fake-baseline.json', 'evidence/fake-attack.json', 'FORGED — no validator ran', 1)",
		)
		.run(f.id);
	const forgedValidationId = Number(forged.lastInsertRowid);

	// The daemon re-checks only the (forged) row, so it SIGNS. promote() succeeds.
	const promoted = findings.promote(f.id, forgedValidationId);
	assert.equal(promoted.status, "validated");

	// >>> RESIDUAL: the forgery is trusted and submittable. These assertions
	// >>> document the OPEN hole. When a privileged re-validation fix lands they
	// >>> will start failing — that is the signal to flip them to expect refusal.
	assert.equal(
		findings.isValidatedTrustworthy(f.id),
		true,
		"RESIDUAL OPEN: forged passed row is (wrongly) trusted — if this fails, the forge is CLOSED; flip this assertion",
	);
	assert.equal(
		findings.markSubmitted(f.id).status,
		"submitted",
		"RESIDUAL OPEN: forged finding is (wrongly) submittable — if this throws, the forge is CLOSED; flip this assertion",
	);
});
