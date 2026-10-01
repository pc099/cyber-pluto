import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { engagementFixture } from "../testing/engagement-fixture.js";
import { resetEngagement } from "./engagement.js";
import { hashEvidence } from "./promotion-evidence.js";
import { recordAndGate } from "../validators/gate.js";
import { recordAttemptStart, recordAttemptEnd } from "../tool-log/attempts-recorder.js";

test("relative and canonical absolute evidence roots write and hash the exact recorded files", async () => {
	const saved = { ...process.env };
	try {
		for (const absolute of [false, true]) {
			const cwd = mkdtempSync(join(tmpdir(), "pluto-evidence-root-"));
			try {
				const engagement = engagementFixture(cwd);
				// Both configurations canonicalize to the same saved association.
				process.env.PLUTO_EVIDENCE_DIR = absolute ? join(cwd, "evidence") : "evidence";
				const finding = engagement.repos.findings.create({ targetId: engagement.targetId });
				await recordAndGate(cwd, engagement, finding.id, {
					validator: "benign_path_fixture", passed: true, diffSummary: "local synthetic path fixture; no target operations",
					baseline: null, attacks: [], steps: [],
				});
				const promotion = engagement.repos.findings.getPromotion(finding.id)!;
				const validation = engagement.repos.validations.listByFinding(finding.id)[0]!;
				assert.equal(promotion.evidence_ref, validation.baseline_ref);
				assert.equal(engagement.repos.findings.isValidatedTrustworthy(finding.id), true);
				assert.ok(validation.baseline_ref && validation.attack_ref);
				for (const ref of [validation.baseline_ref, validation.attack_ref]) {
					assert.ok(resolve(cwd, ref!).startsWith(join(cwd, "evidence/validations/")));
					assert.ok(existsSync(resolve(cwd, ref!)));
				}
				const ref = promotion.evidence_ref;
				const contents = readFileSync(resolve(cwd, ref));
				assert.equal(contents.toString(), "null");
				const expected = createHash("sha256").update(ref).update("\0").update(contents).update("\0").digest("hex");
				assert.equal(hashEvidence(cwd, [ref]), expected);
				assert.notEqual(expected, "");
				if (absolute) assert.equal(existsSync(join(cwd, ref)), false, "never duplicate cwd before an absolute evidence ref");
				recordAttemptStart("benign-tool", "fixture", { note: "local metadata only" });
				await recordAttemptEnd(cwd, "benign-tool", false, { content: [{ type: "text", text: "benign fixture" }] });
				const attempt = engagement.db.prepare("SELECT output_ref FROM attempts ORDER BY id DESC LIMIT 1").get() as { output_ref: string };
				assert.ok(resolve(cwd, attempt.output_ref).startsWith(join(cwd, "evidence/attempts/")));
				assert.match(readFileSync(resolve(cwd, attempt.output_ref), "utf8"), /benign fixture/);
			} finally { resetEngagement(); rmSync(cwd, { recursive: true, force: true }); }
		}
	} finally {
		for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
		Object.assign(process.env, saved);
	}
});
