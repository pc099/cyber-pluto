import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createFindingsRepo } from "../state/findings-repo.js";
import { engagementFixture } from "../testing/engagement-fixture.js";
import { recordAndGate } from "./gate.js";

test("Gate output and orchestration distinguish an unsigned recorded reproduction from a verified current result", async () => {
	for (const signed of [true, false]) {
		const cwd = mkdtempSync(join(tmpdir(), "pluto-gate-trust-"));
		const engagement = engagementFixture(cwd);
		if (!signed) engagement.repos.findings = createFindingsRepo(engagement.db);
		const finding = engagement.repos.findings.create({ targetId: engagement.targetId });
		const result = await recordAndGate(cwd, engagement, finding.id, {
			validator: "command_injection", passed: true, diffSummary: "synthetic fixture, no target request",
			baseline: null, attacks: [], steps: [],
		});
		const text = result.content.filter(c => c.type === "text").map(c => c.text).join("\n");
		const details = result.details as { verified: boolean; footholdSeeded: boolean };
		assert.equal(details.verified, signed);
		assert.equal(details.footholdSeeded, signed);
		assert.equal(engagement.repos.findings.hasValidatedFootholdClass(engagement.targetId, ["command_injection"]), signed);
		assert.match(text, signed ? /VERIFIED CURRENT ATTESTATION/ : /REPRODUCTION RECORDED — UNVERIFIED/);
		assert.equal(engagement.repos.nodes.listByTarget(engagement.targetId).some(n => n.label.startsWith("[privesc]")), signed);
	}
});
