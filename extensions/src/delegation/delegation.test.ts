/**
 * Delegation tests. The load-bearing property (§10.4 / Session 5 contract):
 * the red-lines gate propagates into EVERY delegated sub-agent. We prove it
 * structurally — a sub-agent cannot be spawned without red-lines, for any
 * specialist — since spawn.ts is the single chokepoint that builds the
 * extension set. (The end-to-end block is exercised in the live demo.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildSubAgentArgs, specialistExtensions } from "./spawn.js";

const RED_LINES = "extensions/src/red-lines/index.ts";
const TOOL_LOG = "extensions/src/tool-log/index.ts";

test("every specialist's extension set includes the red-lines gate first", () => {
	for (const specialist of ["exploitation", "recon", "analyst"]) {
		const exts = specialistExtensions(specialist);
		assert.ok(exts.includes(RED_LINES), `${specialist} must load red-lines`);
		assert.ok(exts.includes(TOOL_LOG), `${specialist} must load tool-log`);
		// red-lines is first — the gate is present before any specialist tool.
		assert.equal(exts[0], RED_LINES, `${specialist} must load red-lines first`);
	}
});

test("an unknown specialist falls back to a safe set (still red-lined, no offensive tools)", () => {
	const exts = specialistExtensions("totally-unknown");
	assert.ok(exts.includes(RED_LINES));
	assert.ok(!exts.some((e) => e.includes("/exploit/")), "unknown specialist gets no offensive tools");
});

test("buildSubAgentArgs emits -e red-lines and runs ephemeral (--no-session)", () => {
	const args = buildSubAgentArgs({
		model: "claude-haiku-4-5",
		prompt: "do the thing",
		extensions: specialistExtensions("exploitation"),
	});
	assert.ok(args.includes("--no-session"), "sub-agent must be ephemeral");
	// Every extension is passed with its own -e flag.
	const eIdx = args.indexOf("-e");
	assert.notEqual(eIdx, -1);
	assert.ok(args.includes(RED_LINES));
	// The prompt is passed via -p.
	assert.ok(args.includes("-p"));
});
