/**
 * Privilege-escalation validator tests (Gate 1, §4.5). Root must be a
 * REPRODUCED fact, not a transcript claim — and crucially, a template that
 * merely *claims* root (a spoofed uid banner) must NOT pass, because the
 * root-only read differential it cannot fake is what carries the verdict.
 *
 * The behavioral tests use a REAL privilege boundary (runuser → nobody vs the
 * root test process), so they only run when the suite runs as root (the
 * droplet). Elsewhere they skip with a note; the pure-logic guards always run.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { validatePrivilegeEscalation } from "./privilege-escalation.js";

const asRoot = typeof process.getuid === "function" && process.getuid() === 0;
const rootOnly = { skip: asRoot ? false : "requires running as root (real privilege differential)" };

// A template that runs {probe} genuinely as root (the test process itself).
const ROOT_EXEC = "bash -c {probe}";
// A template that runs {probe} genuinely as an unprivileged user.
const NOBODY_EXEC = "runuser -u nobody -- bash -c {probe}";

test("both templates must contain the {probe} placeholder or validation cannot run", async () => {
	const r = await validatePrivilegeEscalation({ baselineExecTemplate: "id", escalatedExecTemplate: "sudo {probe}" });
	assert.equal(r.passed, false);
	assert.equal(r.technicalSignal, false);
	assert.match(r.diffSummary, /\{probe\}/);
});

test("a canned root banner that never runs our probe does not pass (nonce guard)", async () => {
	// The escalated template ignores {probe} and just prints a fake root line.
	// Our probe's nonce is therefore absent, so nothing is accepted.
	const r = await validatePrivilegeEscalation({
		baselineExecTemplate: NOBODY_EXEC,
		escalatedExecTemplate: "bash -c 'echo uid=0(root)' # {probe}",
	});
	assert.equal(r.technicalSignal, false, "a banner with no nonce is not a real run");
	assert.equal(r.passed, false);
});

test("a genuine escalation (root channel) reproduces and PASSES", rootOnly, async () => {
	const r = await validatePrivilegeEscalation({ baselineExecTemplate: NOBODY_EXEC, escalatedExecTemplate: ROOT_EXEC });
	assert.equal(r.passed, true, r.diffSummary);
	assert.equal(r.validator, "privilege_escalation");
	assert.equal(r.technicalSignal, true);
	assert.equal(r.impactArtifact, true);
	assert.ok(r.steps.every((s) => s.passed), `all steps pass: ${JSON.stringify(r.steps)}`);
	// Do-no-harm: the shadow CONTENT is never captured — only exit codes.
	const blob = JSON.stringify(r);
	assert.ok(!/root:\$[0-9]\$/.test(blob), "no shadow hash content is retained in the report");
});

test("a spoofed uid=0 that CANNOT read shadow does NOT pass (impact-artifact carries the verdict)", rootOnly, async () => {
	// Runs our probe as nobody (so the nonce is really echoed) but rewrites the
	// uid line to look like root. The euid signal is faked; the root-only read
	// differential is not — nobody still cannot read shadow, so it fails.
	const SPOOF = "runuser -u nobody -- bash -c {probe} 2>/dev/null | sed 's/uid=[0-9]*(nobody)/uid=0(root)/'";
	const r = await validatePrivilegeEscalation({ baselineExecTemplate: NOBODY_EXEC, escalatedExecTemplate: SPOOF });
	assert.equal(r.technicalSignal, true, "the uid banner was successfully spoofed to root");
	assert.equal(r.impactArtifact, false, "but shadow could not actually be read");
	assert.equal(r.passed, false, "a fakeable banner without the read differential must not pass");
	assert.match(r.diffSummary, /banner|differential/i);
});

test("an already-root baseline is not counted as an escalation", rootOnly, async () => {
	// Both channels are root: there is no unprivileged starting point to escalate
	// FROM, so there is nothing to prove.
	const r = await validatePrivilegeEscalation({ baselineExecTemplate: ROOT_EXEC, escalatedExecTemplate: ROOT_EXEC });
	assert.equal(r.passed, false);
	assert.match(r.diffSummary, /already root/i);
});
