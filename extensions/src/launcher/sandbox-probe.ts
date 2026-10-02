#!/usr/bin/env node
/** Trusted local readiness fixtures only. No Pi/provider/target invocation.
 * Synthetic passed rows test signing plumbing, not independent validation. */
import assert from "node:assert/strict";
import { openSync, closeSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { checkSignerHealth } from "../state/signer-health.js";
import { createFindingsRepo } from "../state/findings-repo.js";
import { resolveSigner } from "../state/promotion-signer.js";
import { resolveVerifier } from "../state/promotion-verifier.js";

function required(name: string): string {
	const value = process.env[name];
	if (!value) throw new Error(`Readiness fixture missing ${name}`);
	return value;
}
function writeDenied(path: string): void {
	assert.throws(() => { const descriptor = openSync(path, "wx", 0o600); closeSync(descriptor); }, (error: unknown) => ["EACCES", "EPERM", "EROFS"].includes((error as NodeJS.ErrnoException).code ?? ""), `write must be denied: ${path}`);
}
async function main(): Promise<void> {
	assert.equal(required("PLUTO_READINESS_ONLY"), "1");
	assert.equal(process.getuid?.(), Number(required("PLUTO_READINESS_UID")));
	assert.match(readFileSync("/proc/self/status", "utf8"), /^NoNewPrivs:\s+1$/m);
	assert.equal(process.env.PLUTO_PROMOTION_PRIVKEY, undefined);
	const runtime = required("PLUTO_CWD");
	const state = required("PLUTO_STATE_DIR");
	const runId = required("PLUTO_SIGNER_RUN_ID");
	writeDenied(join(runtime, `readiness-${runId}`));
	writeDenied(join(required("PLUTO_CONTROL_DIR"), `readiness-${runId}`));
	writeDenied(join(required("PLUTO_SIGNER_DIR"), `readiness-${runId}`));
	assert.throws(() => readFileSync(required("PLUTO_READINESS_KEY_DENY_PATH")), /EACCES|EPERM/);
	assert.throws(() => readFileSync("/root/cyber-pluto/progress/PROGRESS.md"), /EACCES|EPERM|ENOENT/);
	const writable = join(state, `readiness-${runId}`);
	writeFileSync(writable, "local fixture\n", { flag: "wx", mode: 0o600 });
	assert.equal(readFileSync(writable, "utf8"), "local fixture\n"); unlinkSync(writable);
	const temporary = `/tmp/pluto-readiness-${runId}`;
	writeFileSync(temporary, "private temporary fixture", { flag: "wx", mode: 0o600 });
	assert.match(readFileSync("/proc/self/mountinfo", "utf8"), / \/tmp .* - tmpfs /);
	const signer = resolveSigner();
	const verifier = resolveVerifier();
	assert.ok(signer); assert.ok(verifier);
	await checkSignerHealth({ socketPath: join(required("PLUTO_SIGNER_DIR"), "promotion.sock"), ledgerPath: join(state, "pluto.db"), runId, publicKeyPath: required("PLUTO_PROMOTION_PUBKEY") });
	const database = new DatabaseSync(join(state, "pluto.db"));
	try {
		database.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;");
		const target = Number(database.prepare("INSERT INTO targets(label,host,scope_notes) VALUES('readiness-fixture','fixture.invalid','local fixture only')").run().lastInsertRowid);
		const findings = createFindingsRepo(database, { signer, verifier });
		const signed = findings.create({ targetId: target });
		const validation = Number(database.prepare("INSERT INTO validations(finding_id,validator,baseline_ref,passed) VALUES(?,'readiness-fixture','synthetic-local-fixture',1)").run(signed.id).lastInsertRowid);
		findings.promote(signed.id, validation);
		assert.equal(findings.isValidatedTrustworthy(signed.id), true);
		const flipped = findings.create({ targetId: target });
		database.prepare("UPDATE findings SET status='validated' WHERE id=?").run(flipped.id);
		assert.equal(findings.isValidatedTrustworthy(flipped.id), false);
		assert.throws(() => findings.markSubmitted(flipped.id), /verified current/);
		const failed = findings.create({ targetId: target });
		const failedValidation = Number(database.prepare("INSERT INTO validations(finding_id,validator,passed) VALUES(?,'readiness-fixture',0)").run(failed.id).lastInsertRowid);
		assert.throws(() => signer({ findingId: failed.id, validationId: failedValidation, validator: "readiness-fixture", targetId: target, evidenceRef: "" }), /did not pass/);
	} finally { database.close(); }
	process.stdout.write(`${JSON.stringify({ sandboxReadinessFixture: "passed", uid: process.getuid?.(), noNewPrivileges: true, syntheticSignedPromotion: true, directFlipRefused: true, privateTemporaryPath: temporary, fullPiProfile: "not exercised by this probe", targetExecution: "none" })}\n`);
}
if (process.argv[1]?.endsWith("launcher/sandbox-probe.js")) void main().catch(error => { process.stderr.write(`Sandbox readiness failed: ${String(error)}\n`); process.exitCode = 1; });
