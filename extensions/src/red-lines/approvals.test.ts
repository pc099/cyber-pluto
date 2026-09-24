/**
 * Red-line approval-channel tests. The board's non-negotiables, asserted:
 * exact-command scope (a reworded command re-blocks), single-use, TTL,
 * session-binding, category isolation, and signature verification (a forged or
 * unsigned grant fails when a key is in force).
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { buildGrant, commandHash, DEFAULT_GRANT_TTL_MS, grantMatches, type PendingBlock, signGrant, verifyGrant } from "./approvals.js";
import { appendGrant, consumeMatchingGrant, readPendingBlocks, recordPendingBlock } from "./approvals-store.js";

const KEY = "test-approval-hmac-key-0123456789";

function block(over: Partial<PendingBlock> = {}): PendingBlock {
	const toolName = over.toolName ?? "bash";
	const cmd = "curl -sk https://10.0.0.5:20000/";
	return {
		ts: new Date().toISOString(),
		blockId: "b1",
		sessionId: "S1",
		toolName,
		category: over.category ?? "safety_of_life_systems",
		ruleId: "safety-of-life",
		reason: "x",
		commandPreview: cmd,
		commandHash: over.commandHash ?? commandHash(toolName, cmd),
		...over,
	};
}

test("commandHash is deterministic and command-specific", () => {
	assert.equal(commandHash("bash", "id"), commandHash("bash", "id"));
	assert.notEqual(commandHash("bash", "id"), commandHash("bash", "id "));
	assert.notEqual(commandHash("bash", "id"), commandHash("powershell", "id"));
});

test("a grant matches only the EXACT command it was issued for (reword re-blocks)", () => {
	const g = buildGrant({ block: block(), approver: "op", ttlMs: DEFAULT_GRANT_TTL_MS, now: Date.now(), key: KEY });
	const base = { sessionId: "S1", now: Date.now(), key: KEY };
	assert.ok(grantMatches(g, { ...base, toolName: "bash", commandText: "curl -sk https://10.0.0.5:20000/" }), "exact command matches");
	assert.ok(!grantMatches(g, { ...base, toolName: "bash", commandText: "curl -sk https://10.0.0.5:20000/x" }), "a reworded command does NOT match");
});

test("a grant does not cross sessions or tools", () => {
	const g = buildGrant({ block: block(), approver: "op", ttlMs: DEFAULT_GRANT_TTL_MS, now: Date.now(), key: KEY });
	const cmd = "curl -sk https://10.0.0.5:20000/";
	assert.ok(!grantMatches(g, { sessionId: "OTHER", toolName: "bash", commandText: cmd, now: Date.now(), key: KEY }), "different session");
	assert.ok(!grantMatches(g, { sessionId: "S1", toolName: "powershell", commandText: cmd, now: Date.now(), key: KEY }), "different tool");
});

test("a grant expires", () => {
	const now = Date.now();
	const g = buildGrant({ block: block(), approver: "op", ttlMs: 1000, now, key: KEY });
	const p = { sessionId: "S1", toolName: "bash", commandText: "curl -sk https://10.0.0.5:20000/", key: KEY };
	assert.ok(grantMatches(g, { ...p, now: now + 500 }), "within TTL");
	assert.ok(!grantMatches(g, { ...p, now: now + 2000 }), "past TTL");
});

test("with a key in force, an unsigned or forged grant does NOT match", () => {
	const now = Date.now();
	const g = buildGrant({ block: block(), approver: "op", ttlMs: DEFAULT_GRANT_TTL_MS, now, key: KEY });
	const p = { sessionId: "S1", toolName: "bash", commandText: "curl -sk https://10.0.0.5:20000/", now, key: KEY };
	assert.ok(grantMatches(g, p), "validly signed matches");
	assert.ok(verifyGrant(g, KEY));
	// Strip the signature (what a model forging the file directly would produce).
	const unsigned = { ...g, sig: undefined };
	assert.ok(!grantMatches(unsigned, p), "unsigned grant rejected when a key is enforced");
	// Tamper a field but keep the old sig.
	const tampered = { ...g, category: "destructive_or_irreversible" };
	assert.ok(!verifyGrant(tampered, KEY), "tampered grant fails verification");
	// Wrong key.
	assert.ok(!verifyGrant(g, "another-key-000000000000000000"), "a different key does not verify");
});

test("store round-trip: record a block, grant it, consume it ONCE", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-approvals-"));
	// The state dir is <cwd> for this harness path; recordPendingBlock creates it.
	const b = block({ sessionId: "SX", blockId: "b9" });
	recordPendingBlock(cwd, b);
	// idempotent surfacing
	recordPendingBlock(cwd, b);
	const pending = readPendingBlocks(cwd);
	assert.equal(pending.filter((x) => x.blockId === "b9").length, 1, "block surfaced once (deduped)");

	const g = buildGrant({ block: b, approver: "op", ttlMs: DEFAULT_GRANT_TTL_MS, now: Date.now(), key: KEY });
	appendGrant(cwd, g);
	const params = { sessionId: "SX", toolName: "bash", commandText: "curl -sk https://10.0.0.5:20000/", now: Date.now(), key: KEY };
	assert.ok(consumeMatchingGrant(cwd, params), "first use consumes the grant");
	assert.equal(consumeMatchingGrant(cwd, params), null, "single-use: the second attempt finds nothing");
});

test("category isolation: a grant for one category cannot ride a different dangerous command", () => {
	// Because scope is the exact-command hash, a grant for the :20000 curl simply
	// does not match an rm -rf command at all — categories never leak.
	const g = buildGrant({ block: block(), approver: "op", ttlMs: DEFAULT_GRANT_TTL_MS, now: Date.now(), key: KEY });
	assert.ok(!grantMatches(g, { sessionId: "S1", toolName: "bash", commandText: "rm -rf /", now: Date.now(), key: KEY }));
});
