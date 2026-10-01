/**
 * Engagement-lifecycle tests (§10.5). Each mechanism must fire when it should
 * and NOT when it shouldn't — crucially, a bypass/evasion mutation must read as
 * progress, not a stall (§6.5.2). These test the deterministic check functions,
 * which is where the logic lives; the hook only wires them to the tool path.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
	checkHardCaps,
	checkTryBudget,
	classifyAttack,
	DEFAULT_TRY_BUDGET,
	detectStuck,
	detectUnhealthy,
	INITIAL_NO_PROGRESS_STATE,
	noProgressStalled,
	type ProgressFingerprint,
	repeatCount,
	sameProgress,
	updateNoProgress,
} from "./checks.js";
import { buildRunSummary, milestoneRank } from "./run-summary.js";

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

// --- Try-budget: pivot before grinding an expensive/low-yield class ---------

test("classifyAttack buckets brute/crack/fuzz and leaves ordinary commands alone", () => {
	assert.equal(classifyAttack("hydra -l admin -P rockyou.txt 10.0.0.5 ssh"), "brute_auth");
	assert.equal(classifyAttack("medusa -h 10.0.0.5 -u root -P list -M ssh"), "brute_auth");
	assert.equal(classifyAttack("john --wordlist=rockyou.txt hash.txt"), "hash_crack");
	assert.equal(classifyAttack("hashcat -m 1800 hash.txt rockyou.txt"), "hash_crack");
	assert.equal(classifyAttack("gobuster dir -u http://10.0.0.5 -w raft-large.txt"), "web_fuzz");
	// A fuzzer used as an auth brute (POST/login/data) is brute_auth, not fuzz.
	assert.equal(classifyAttack("ffuf -u http://10.0.0.5/login -X POST -d 'user=admin&pass=FUZZ' -w rockyou.txt"), "brute_auth");
	// Plain content discovery with ffuf stays web_fuzz.
	assert.equal(classifyAttack("ffuf -u http://10.0.0.5/FUZZ -w raft-large-files.txt -x php"), "web_fuzz");
	assert.equal(classifyAttack("nmap -sV 10.0.0.5"), null);
	assert.equal(classifyAttack("curl http://10.0.0.5/"), null);
});

test("try-budget passes under the limit and blocks over it, forcing a pivot", () => {
	const prior = Array.from({ length: 4 }, (_, i) => `hydra run ${i}`); // 4 brute attempts so far
	// The 5th (spent=4, limit=5) still passes.
	assert.equal(checkTryBudget({ command: "hydra -l admin -P rockyou 10.0.0.5 ssh", priorCommands: prior, budget: DEFAULT_TRY_BUDGET, hasValidatedFoothold: false }).over, false);
	// A 6th, once 5 are on the ledger (spent=5, limit=5), is blocked.
	const prior5 = [...prior, "hydra -l root -P rockyou 10.0.0.5 ftp"];
	const v = checkTryBudget({ command: "hydra -l admin -P rockyou 10.0.0.5 ssh", priorCommands: prior5, budget: DEFAULT_TRY_BUDGET, hasValidatedFoothold: false });
	assert.equal(v.over, true);
	if (v.over) {
		assert.equal(v.cls, "brute_auth");
		assert.equal(v.spent, 5);
		assert.match(v.guidance, /unauthenticated surface|content discovery/);
	}
});

test("try-budget guidance differs pre- vs post-foothold for auth brute", () => {
	const prior = Array.from({ length: 5 }, (_, i) => `hydra run ${i}`);
	const post = checkTryBudget({ command: "hydra x", priorCommands: prior, budget: DEFAULT_TRY_BUDGET, hasValidatedFoothold: true });
	assert.equal(post.over, true);
	if (post.over) assert.match(post.guidance, /privilege escalation|privesc/i);
});

test("a non-budgeted command is never blocked no matter the history", () => {
	const prior = Array.from({ length: 50 }, (_, i) => `hydra run ${i}`);
	assert.equal(checkTryBudget({ command: "nmap -sV 10.0.0.5", priorCommands: prior, budget: DEFAULT_TRY_BUDGET, hasValidatedFoothold: false }).over, false);
});

test("content discovery gets a high ceiling, not the tight brute ceiling", () => {
	const prior = Array.from({ length: 10 }, (_, i) => `gobuster dir run ${i}`); // 10 fuzz attempts
	// Well under web_fuzz budget (40) — still productive, not blocked.
	assert.equal(checkTryBudget({ command: "gobuster dir -u http://x -w w.txt", priorCommands: prior, budget: DEFAULT_TRY_BUDGET, hasValidatedFoothold: false }).over, false);
});

// --- Run-summary telemetry: milestone derived from ledger facts -------------

function baseSummaryInput() {
	return {
		targetLabel: "box", host: "10.0.0.5", stopReason: "in_progress",
		counts: { candidate: 0, validated: 0, submitted: 0, rejected: 0 },
		untrustedValidated: 0, credsRecovered: 0, nodeCount: 0, attemptCount: 0,
		verifiedCurrentFindings: 0,
		attemptsByClass: {}, hasFoothold: false, hasRoot: false,
		signatureEnforced: true,
		elapsedSeconds: 0, contextTokensSeen: 0,
	};
}

test("run-summary milestone is derived from proven facts, ascending", () => {
	const started = buildRunSummary(baseSummaryInput());
	assert.equal(started.reached, "started");
	assert.equal(buildRunSummary({ ...baseSummaryInput(), attemptCount: 2 }).reached, "recon");
	assert.equal(buildRunSummary({ ...baseSummaryInput(), attemptCount: 5, nodeCount: 6 }).reached, "surface_mapped");
	assert.equal(buildRunSummary({ ...baseSummaryInput(), counts: { candidate: 1, validated: 0, submitted: 0, rejected: 0 } }).reached, "candidate_found");
	assert.equal(buildRunSummary({ ...baseSummaryInput(), hasFoothold: true, verifiedCurrentFindings: 1 }).reached, "foothold");
	assert.equal(buildRunSummary({ ...baseSummaryInput(), credsRecovered: 1 }).reached, "started");
	// Root is the top milestone and dominates everything else.
	assert.equal(buildRunSummary({ ...baseSummaryInput(), hasRoot: true, hasFoothold: true, verifiedCurrentFindings: 2, counts: { candidate: 3, validated: 2, submitted: 0, rejected: 1 } }).reached, "root");
	assert.ok(milestoneRank("root") > milestoneRank("foothold"));
	assert.ok(milestoneRank("foothold") > milestoneRank("candidate_found"));
});

test("unverified booleans cannot yield a root milestone; submitted verified facts remain eligible", () => {
	const input = { ...baseSummaryInput(), hasRoot: true, hasFoothold: true, counts: { candidate: 0, validated: 1, submitted: 0, rejected: 0 } };
	assert.equal(buildRunSummary(input).reached, "candidate_found");
	assert.equal(buildRunSummary({ ...input, signatureEnforced: false, verifiedCurrentFindings: 1 }).reached, "candidate_found");
	assert.equal(buildRunSummary({ ...input, counts: { candidate: 0, validated: 0, submitted: 1, rejected: 0 }, verifiedCurrentFindings: 1 }).reached, "root");
});

test("run-summary discounts signature-failing validated findings (enforcement on)", () => {
	const s = buildRunSummary({ ...baseSummaryInput(), signatureEnforced: true, counts: { candidate: 0, validated: 3, submitted: 0, rejected: 0 }, untrustedValidated: 2 });
	assert.equal(s.trustworthyValidated, 1, "2 of 3 validated fail Gate-1 signature");
	assert.equal(s.untrustedValidatedCount, 2);
	assert.equal(s.unverifiableValidated, 0);
	assert.equal(s.schema, 1);
	assert.equal(s.stopReason, "in_progress");
});

test("run-summary calls unsigned validated UNVERIFIABLE, never trustworthy (enforcement off)", () => {
	// The board catch: with no verifier (non-sandbox dev run), an unsigned
	// promotion does not FAIL a signature — it has none — so it must not be
	// counted as trustworthy. This is the Empire:Breakout #11 situation.
	const s = buildRunSummary({ ...baseSummaryInput(), signatureEnforced: false, counts: { candidate: 0, validated: 1, submitted: 0, rejected: 0 }, untrustedValidated: 0 });
	assert.equal(s.trustworthyValidated, 0, "nothing is trustworthy without a verifier");
	assert.equal(s.unverifiableValidated, 1, "the validated finding is unverifiable, not trusted");
	assert.equal(s.untrustedValidatedCount, 0);
});

// --- No-progress detection: activity without a new ledger fact --------------

function fp(over: Partial<ProgressFingerprint> = {}): ProgressFingerprint {
	return { milestone: 1, candidates: 0, validated: 1, creds: 1, rootValidated: 0, ...over };
}

test("no-progress fires after a window of NOVEL activity with no new fact", () => {
	let st = INITIAL_NO_PROGRESS_STATE;
	const stable = fp();
	// One call establishes the fingerprint, then 20 identical calls (the pty-thrash
	// shape: novel commands, no new fact) accumulate the counter to 20.
	for (let i = 0; i < 21; i++) st = updateNoProgress(st, stable);
	assert.equal(st.callsSinceChange, 20);
	assert.equal(noProgressStalled(st, 20).stalled, true, "unchanged for the window → stalled");
	assert.equal(noProgressStalled(st, 25).stalled, false, "not yet at the larger window");
});

test("any new ledger fact resets the no-progress counter (no false fire on real work)", () => {
	let st = INITIAL_NO_PROGRESS_STATE;
	for (let i = 0; i < 15; i++) st = updateNoProgress(st, fp());
	// A new credential appears (real progress) — counter resets.
	st = updateNoProgress(st, fp({ creds: 2 }));
	assert.equal(st.callsSinceChange, 0, "a changed fingerprint resets the counter");
	assert.equal(noProgressStalled(st, 20).stalled, false);
	// A validated finding, then reaching root — each resets too.
	for (let i = 0; i < 19; i++) st = updateNoProgress(st, fp({ creds: 2 }));
	st = updateNoProgress(st, fp({ creds: 2, rootValidated: 1, milestone: 2 }));
	assert.equal(noProgressStalled(st, 20).stalled, false, "reaching root is progress, not a stall");
});

test("sameProgress compares all fact dimensions", () => {
	assert.ok(sameProgress(fp(), fp()));
	assert.ok(!sameProgress(fp(), fp({ candidates: 1 })));
	assert.ok(!sameProgress(fp(), fp({ rootValidated: 1 })));
});
