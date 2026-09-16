/**
 * Launcher tests — the engagement assembly is now testable code, not untestable
 * shell. Assert that buildPlan turns operator intent into the right env,
 * briefing, and CLI args, and that it never re-assembles the harness stack
 * (that lives in .pi/settings.json; the launcher passes -a, not -e flags).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildPlan } from "./index.js";

function plan(argv: string[]) {
	const r = buildPlan(argv);
	assert.equal(r.kind, "plan", `expected a plan for ${argv.join(" ")}`);
	if (r.kind !== "plan") throw new Error("unreachable");
	return r.plan;
}

test("target becomes scope and drives env + briefing", () => {
	const p = plan(["10.0.0.5", "find", "a", "foothold"]);
	assert.equal(p.target, "10.0.0.5");
	assert.equal(p.env.PLUTO_SCOPE_HOSTS, "10.0.0.5");
	assert.equal(p.env.PLUTO_TARGET_HOST, "10.0.0.5");
	assert.ok(p.briefing.includes("In-scope hosts: 10.0.0.5"));
	assert.ok(p.briefing.includes("Operator objective: find a foothold"));
});

test("the launcher passes -a and NEVER assembles the stack with -e flags", () => {
	const p = plan(["10.0.0.5"]);
	assert.ok(p.cliArgs.includes("-a"), "must trust the .pi/ profile");
	assert.ok(!p.cliArgs.includes("-e"), "the harness stack comes from .pi/settings.json, not -e flags");
	assert.ok(!p.cliArgs.includes("--skill"), "skills come from the profile too");
	assert.ok(p.cliArgs.includes("--append-system-prompt"));
});

test("--scope and --scope adds hosts; scope is de-duped", () => {
	const p = plan(["10.0.0.5", "--scope", "10.0.0.5, 10.0.0.6 10.0.0.7"]);
	assert.equal(p.scopeCsv, "10.0.0.5,10.0.0.6,10.0.0.7");
});

test("--no-cap disables both caps; env reflects it", () => {
	const p = plan(["10.0.0.5", "--no-cap"]);
	assert.equal(p.env.PLUTO_MAX_TOOL_CALLS, "0");
	assert.equal(p.env.PLUTO_MAX_WALLCLOCK_S, "0");
});

test("per-engagement state isolation: PLUTO_STATE_DIR is per-target", () => {
	assert.equal(plan(["10.0.0.5"]).env.PLUTO_STATE_DIR, "engagements/engagement-10-0-0-5/state");
	assert.equal(plan(["ex.com", "--label", "acme"]).env.PLUTO_STATE_DIR, "engagements/acme/state");
});

test("--headless adds -p (one entrypoint, both modes)", () => {
	const interactive = plan(["10.0.0.5"]);
	assert.ok(!interactive.cliArgs.includes("-p"));
	const headless = plan(["10.0.0.5", "--headless"]);
	assert.ok(headless.cliArgs.includes("-p"), "headless runs autonomously via -p");
});

test("phase routing: --attack-provider/-model set the attack env", () => {
	const p = plan(["10.0.0.5", "--provider", "zai", "--attack-provider", "deepseek", "--attack-model", "deepseek-v4-pro"]);
	assert.equal(p.env.PLUTO_ATTACK_PROVIDER, "deepseek");
	assert.equal(p.env.PLUTO_ATTACK_MODEL, "deepseek-v4-pro");
	assert.ok(p.cliArgs.includes("zai"));
});

test("bug-bounty flags produce the compliance briefing + env", () => {
	const p = plan(["ex.com", "--program", "acme", "--traffic-id", "X-Bug-Bounty: me", "--rate", "1"]);
	assert.equal(p.env.PLUTO_PROGRAM, "acme");
	assert.ok(p.briefing.includes("BUG-BOUNTY engagement for program 'acme'"));
	assert.ok(p.briefing.includes("X-Bug-Bounty: me"));
});

test("missing target is an error; unknown flag is an error", () => {
	assert.equal(buildPlan([]).kind, "error");
	assert.equal(buildPlan(["10.0.0.5", "--bogus"]).kind, "error");
	assert.equal(buildPlan(["--help"]).kind, "help");
});
