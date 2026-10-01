import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	classifyProviderError, consumeProviderRetry, getProviderHold, initializeOutcome,
	outcomeHistoryPath, outcomePath, readOutcome, recordCompletedTool, recordHardCap,
	recordLocalInterruption, recordProviderError, recordProviderRecovery,
	requestProviderRetry, retryIsActive, settleOutcome, type OutcomeBinding,
} from "./provider-outcome.js";

const POLICY = "Codex error: This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request.";
const error = (errorMessage: string, fields: Record<string, unknown> = {}) => ({ role: "assistant", stopReason: "error", errorMessage, provider: "fixture", model: "offline", ...fields });
function scratch(t: { after(fn: () => void): void }, id = "session-one"): OutcomeBinding {
	const directory = mkdtempSync(join(tmpdir(), "pluto-outcome-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return { sessionId: id, sessionFile: join(directory, "session.jsonl") };
}

test("policy classification requires an actual assistant error, not quoted ordinary output", () => {
	assert.equal(classifyProviderError(error(POLICY))?.category, "provider_blocked");
	assert.equal(classifyProviderError({ ...error(POLICY), stopReason: "stop" }), undefined);
	assert.equal(classifyProviderError({ ...error(POLICY), role: "user" }), undefined);
	assert.equal(classifyProviderError(error(`Quoted example: ${POLICY}`))?.category, "provider_other");
	assert.equal(classifyProviderError(error("Contains cyber_policy in prose"))?.category, "provider_other");
});

test("genuine structured codes and transport/auth/rate errors remain distinct", () => {
	assert.equal(classifyProviderError(error(JSON.stringify({ error: { code: "cyber_policy" } })))?.category, "provider_blocked");
	assert.equal(classifyProviderError(error("opaque", { diagnostics: [{ error: { code: "cyber_policy" } }] }))?.category, "provider_blocked");
	assert.equal(classifyProviderError(error("opaque", { error: { code: 401 } }))?.category, "authentication");
	assert.equal(classifyProviderError(error("opaque", { error: { code: 429 } }))?.category, "rate_limit");
	assert.equal(classifyProviderError(error("fetch failed"))?.category, "network");
	assert.equal(classifyProviderError(error("opaque", { error: { code: "ECONNRESET" } }))?.category, "network");
	assert.equal(classifyProviderError(error("opaque", { error: { code: 403 } }))?.category, "provider_other");
});

test("error summaries and safe identifiers never persist raw error credentials or full prompts", t => {
	const binding = scratch(t);
	const message = error(`${POLICY} password=synth-password https://fake.invalid/?token=synth-token`, { responseId: "req_fixture", content: [{ type: "text", text: "synthetic private prompt" }] });
	const original = JSON.stringify(message);
	recordProviderError(binding, classifyProviderError(message)!);
	const persisted = readFileSync(outcomePath(binding), "utf8") + readFileSync(outcomeHistoryPath(binding), "utf8");
	assert.equal(persisted.includes("synth-password"), false);
	assert.equal(persisted.includes("synth-token"), false);
	assert.equal(persisted.includes("synthetic private prompt"), false);
	assert.equal(readOutcome(binding)?.lastError?.responseId, "req_fixture");
	assert.equal(readOutcome(binding)?.lastError?.requestId, undefined, "response identity is not relabeled as request identity");
	assert.equal(JSON.stringify(message), original, "original error object is unchanged");
});

test("request and response identifiers remain distinct when both are actually captured", () => {
	const classified = classifyProviderError(error(POLICY, { responseId: "response_fixture", requestId: "request_fixture" }));
	assert.equal(classified?.responseId, "response_fixture");
	assert.equal(classified?.requestId, "request_fixture");
});

test("provider-only failure is durable and retains the last completed dummy tool", t => {
	const binding = scratch(t);
	initializeOutcome(binding);
	recordCompletedTool(binding, { toolCallId: "call_fixture|fc_fixture", toolName: "dummy", completedAt: new Date().toISOString(), isError: false });
	recordProviderError(binding, classifyProviderError(error(POLICY))!);
	settleOutcome(binding);
	const reopened = readOutcome({ ...binding });
	assert.equal(reopened?.providerBlocked, true);
	assert.equal(reopened?.lastCompletedTool?.toolCallId, "call_fixture|fc_fixture");
	assert.equal(getProviderHold(binding).blocked, true);
	assert.equal(reopened?.executionState, "unknown");
	assert.equal(reopened?.cleanupState, "unknown");
});

test("operator retry is one-shot and cannot be reused after restart or clear prior history", t => {
	const binding = scratch(t);
	recordProviderError(binding, classifyProviderError(error(POLICY))!);
	requestProviderRetry(binding, "operator reviewed access state");
	assert.equal(getProviderHold(binding).blocked, true, "issuing retry does not lift child holds");
	assert.equal(consumeProviderRetry(binding, "runtime-a"), true);
	assert.equal(consumeProviderRetry(binding, "runtime-a"), false);
	assert.equal(retryIsActive(binding, "runtime-a"), true);
	assert.equal(retryIsActive(binding, "runtime-b"), false);
	recordProviderRecovery(binding, "runtime-b");
	assert.equal(getProviderHold(binding).blocked, true);
	recordProviderRecovery(binding, "runtime-a");
	assert.equal(getProviderHold(binding).blocked, false);
	const terminal = settleOutcome(binding);
	assert.equal(terminal.state, "awaiting_operator");
	assert.equal(terminal.terminalReason, "awaiting_operator");
	assert.equal(terminal.executionState, "unknown");
	const events = readFileSync(outcomeHistoryPath(binding), "utf8").trim().split("\n").map(line => JSON.parse(line));
	assert.ok(events.some(event => event.kind === "provider_error"));
	assert.ok(events.some(event => event.kind === "provider_recovered"));
});

test("retry failures retain policy hold even if the latest error is network, and permit a new deliberate attempt", t => {
	const binding = scratch(t);
	recordProviderError(binding, classifyProviderError(error(POLICY))!);
	requestProviderRetry(binding, "operator retry");
	consumeProviderRetry(binding, "runtime");
	recordProviderError(binding, classifyProviderError(error("fetch failed"))!);
	assert.equal(getProviderHold(binding).reason, "provider_blocked");
	assert.equal(retryIsActive(binding, "runtime"), false);
	requestProviderRetry(binding, "operator reviewed transport");
	assert.equal(consumeProviderRetry(binding, "runtime"), true);
});

test("hard cap wins over provider errors, settlement, successful replies and retry requests", t => {
	const binding = scratch(t);
	recordHardCap(binding, "hard_cap:wall_clock");
	recordProviderError(binding, classifyProviderError(error(POLICY))!);
	recordProviderRecovery(binding, "runtime");
	settleOutcome(binding);
	assert.equal(readOutcome(binding)?.terminalReason, "hard_cap:wall_clock");
	assert.equal(readOutcome(binding)?.state, "hard_cap");
	assert.throws(() => requestProviderRetry(binding, "operator retry"), /hard cap/);
	assert.equal(consumeProviderRetry(binding, "runtime"), false);
});

test("fork inherits interruption and run clock but not parent tool attribution/retry", t => {
	const parent = scratch(t);
	recordCompletedTool(parent, { toolCallId: "parent-tool", toolName: "dummy", completedAt: new Date().toISOString(), isError: false });
	recordProviderError(parent, classifyProviderError(error(POLICY))!);
	requestProviderRetry(parent, "parent authorization");
	const child = scratch(t, "fork-session");
	const inherited = readOutcome(parent)!;
	const state = initializeOutcome(child, inherited);
	assert.equal(state.providerBlocked, true);
	assert.equal(state.startedAt, inherited.startedAt);
	assert.equal(state.lastCompletedTool, undefined);
	assert.equal(state.retryAllowance, undefined);
});

test("projection recovers from committed journal without losing a blocked state", t => {
	const binding = scratch(t);
	recordProviderError(binding, classifyProviderError(error(POLICY))!);
	unlinkSync(outcomePath(binding));
	assert.equal(readOutcome(binding)?.providerBlocked, true);
	settleOutcome(binding);
	assert.equal(JSON.parse(readFileSync(outcomePath(binding), "utf8")).providerBlocked, true);
});

test("conflicting session descriptors and torn journal writes fail closed", t => {
	const binding = scratch(t);
	initializeOutcome(binding);
	assert.throws(() => readOutcome({ ...binding, sessionId: "other-session" }), /conflict/i);
	writeFileSync(outcomeHistoryPath(binding), "{torn-record", { flag: "a" });
	assert.throws(() => getProviderHold(binding), /Corrupt/);
});

test("nonpolicy recovery is recorded, ordinary settlement never implies engagement completion", t => {
	const binding = scratch(t);
	recordProviderError(binding, classifyProviderError(error("fetch failed"))!);
	assert.equal(getProviderHold(binding).blocked, false);
	recordProviderRecovery(binding, "runtime");
	assert.equal(readOutcome(binding)?.lastError, undefined);
	recordLocalInterruption(binding, "scope_denied");
	assert.equal(settleOutcome(binding).terminalReason, "scope_denied");
	assert.equal(readOutcome(binding)?.state, "awaiting_operator");
});
