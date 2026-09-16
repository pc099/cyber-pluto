/**
 * Engagement-lifecycle tests (§10.5). Each mechanism must fire when it should
 * and NOT when it shouldn't — crucially, a bypass/evasion mutation must read as
 * progress, not a stall (§6.5.2). These test the deterministic check functions,
 * which is where the logic lives; the hook only wires them to the tool path.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { checkHardCaps, detectStuck, detectUnhealthy, repeatCount } from "./checks.js";

const CAPS = { maxToolCalls: 200, maxWallClockSeconds: 3600, maxTokens: 4_000_000 };

test("hard caps fire on tool-call count, wall-clock, and tokens, else pass", () => {
	assert.equal(checkHardCaps(199, 10, 1_000_000, CAPS).stop, false);
	const byCalls = checkHardCaps(200, 10, 0, CAPS);
	assert.equal(byCalls.stop, true);
	if (byCalls.stop) assert.equal(byCalls.kind, "tool_calls");
	const byTime = checkHardCaps(5, 3600, 0, CAPS);
	assert.equal(byTime.stop, true);
	if (byTime.stop) assert.equal(byTime.kind, "wall_clock");
	const byTokens = checkHardCaps(5, 10, 4_000_000, CAPS);
	assert.equal(byTokens.stop, true);
	if (byTokens.stop) assert.equal(byTokens.kind, "tokens");
});

test("environmental pause detects each target-health signal, ignores healthy output", () => {
	assert.equal(detectUnhealthy("Please complete the CAPTCHA to continue"), "captcha");
	assert.equal(detectUnhealthy("429 Too Many Requests, retry-after: 60"), "rate_limited");
	assert.equal(detectUnhealthy("Your account is locked due to too many failed login attempts"), "account_locked");
	assert.equal(detectUnhealthy("curl: (7) Connection refused"), "unresponsive");
	assert.equal(detectUnhealthy("Request blocked by Cloudflare"), "waf");
	assert.equal(detectUnhealthy('{"rows":[{"id":1,"name":"widget"}]}'), null);
});

test("stuck fires on a repeated identical call", () => {
	const recent = ["nmap -sV 10.0.0.5", "nmap -sV 10.0.0.5", "nmap -sV 10.0.0.5"];
	const v = detectStuck({ command: "nmap -sV 10.0.0.5", recentCommands: recent, repeatThreshold: 3, nodeCountAtWindowStart: 5, nodeCountNow: 5 });
	assert.equal(v.stuck, true);
	if (v.stuck) assert.equal(v.signal, "repeated_call");
});

test("a bypass/evasion mutation is PROGRESS, not a stall (§6.5.2)", () => {
	// Same target, but each attempt is a different WAF-evasion payload.
	const recent = [
		"sqlmap -u http://t/ --tamper=space2comment",
		"sqlmap -u http://t/ --tamper=charencode",
		"sqlmap -u http://t/ --tamper=between",
	];
	const v = detectStuck({ command: "sqlmap -u http://t/ --tamper=equaltolike", recentCommands: recent, repeatThreshold: 3, nodeCountAtWindowStart: 5, nodeCountNow: 5 });
	assert.equal(v.stuck, false, "distinct evasion attempts must not trip stuck detection");
});

test("stuck fires on no-new-nodes while circling a small command set", () => {
	// Low variation (2 calls alternating) with no tree growth = genuine circling.
	const recent = ["a", "b", "a", "b"];
	const v = detectStuck({ command: "a", recentCommands: recent, repeatThreshold: 3, nodeCountAtWindowStart: 7, nodeCountNow: 7 });
	assert.equal(v.stuck, true);
	if (v.stuck) assert.equal(v.signal, "no_new_nodes");
});

test("growing the tree clears the no-new-nodes stall", () => {
	const recent = ["a", "b", "a", "b"];
	const v = detectStuck({ command: "a", recentCommands: recent, repeatThreshold: 3, nodeCountAtWindowStart: 7, nodeCountNow: 9 });
	assert.equal(v.stuck, false);
});

test("repeatCount matches only exact commands", () => {
	assert.equal(repeatCount("x -a", ["x -a", "x -b", " x -a "]), 2);
	assert.equal(repeatCount("x -a", ["x -b", "x -c"]), 0);
});
