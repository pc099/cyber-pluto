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
import { writeFileSync, unlinkSync } from "node:fs";
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

test("a baseline whose READ MECHANISM is broken does not pass (false-positive guard)", async () => {
	// Board-found false positive: if the baseline's read probe fails for a
	// NON-permission reason (a mis-quoted/mangled template), its rc!=0 must NOT be
	// counted as a permission denial. Model it cleanly: a baseline channel where
	// `id` reports a normal unprivileged user but EVERY `cat` fails (rc 1) for a
	// non-permission reason. Even the world-readable control file then fails, so
	// the validator must refuse rather than pass on an untrustworthy differential.
	// A BASH_ENV rcfile injects the two shell functions into the (non-interactive)
	// bash the validator runs, without any quoting collision.
	const rc = `/tmp/pluto-privtest-brokenreads-${process.pid}.sh`;
	writeFileSync(rc, "cat(){ return 1; }\nid(){ echo 'uid=1000(cyber) gid=1000(cyber)'; }\n");
	try {
		const BROKEN_READS = `BASH_ENV=${rc} bash -c {probe}`;
		const r = await validatePrivilegeEscalation({ baselineExecTemplate: BROKEN_READS, escalatedExecTemplate: ROOT_EXEC });
		const base = r.steps.find((s) => s.name === "baseline-unprivileged");
		assert.ok(base?.passed, "baseline should look like a normal non-root user (id works)");
		const ctl = r.steps.find((s) => s.name === "baseline-read-mechanism");
		assert.ok(ctl && !ctl.passed, "the control-read step should be present and FAILING");
		assert.equal(r.impactArtifact, false, "a denial for the wrong reason must not count as a real differential");
		assert.equal(r.passed, false, "must not pass when the baseline read mechanism is unverified");
		assert.match(r.diffSummary, /control|broken|mis-quoted|template/i);
	} finally {
		try { unlinkSync(rc); } catch { /* best effort */ }
	}
});

test("a mis-quoted template that makes baseline run as root yields an actionable quoting hint", rootOnly, async () => {
	// The exact run-lesson: quoting the placeholder collides with the validator's
	// own quoting and pushes the baseline to root. The rejection must tell the
	// operator to pass a BARE {probe}, not leave them guessing for 4 tries.
	const r = await validatePrivilegeEscalation({ baselineExecTemplate: ROOT_EXEC, escalatedExecTemplate: ROOT_EXEC });
	assert.equal(r.passed, false);
	const base = r.steps.find((s) => s.name === "baseline-unprivileged");
	assert.ok(base && /bare \{probe\}|quoted/i.test(base.detail), `expected a quoting hint, got: ${base?.detail}`);
});

test("an already-root baseline is not counted as an escalation", rootOnly, async () => {
	// Both channels are root: there is no unprivileged starting point to escalate
	// FROM, so there is nothing to prove.
	const r = await validatePrivilegeEscalation({ baselineExecTemplate: ROOT_EXEC, escalatedExecTemplate: ROOT_EXEC });
	assert.equal(r.passed, false);
	assert.match(r.diffSummary, /already root/i);
});
