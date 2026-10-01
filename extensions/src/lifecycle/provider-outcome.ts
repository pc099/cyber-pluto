/** Durable interruption telemetry. This is continuity metadata, not a privileged
 * attestation or an execution journal. Nothing here retries a provider or replays
 * target work. Full sanitized event history is append-only; the atomic sidecar
 * is a projection recoverable from that history after a partial write. */
import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { dirname } from "node:path";
import { redactSecrets } from "../shared/redact.js";

export interface OutcomeBinding { sessionId: string; sessionFile: string }
export type ProviderErrorCategory = "provider_blocked" | "authentication" | "rate_limit" | "network" | "provider_other";
export interface ClassifiedProviderError {
	category: ProviderErrorCategory;
	summary: string;
	provider?: string;
	model?: string;
	requestId?: string;
	responseId?: string;
	fingerprint: string;
}
export interface CompletedToolReference { toolCallId: string; toolName: string; completedAt: string; isError: boolean }
export interface ProviderOutcome {
	schema: 1;
	sessionId: string;
	sequence: number;
	updatedAt: string;
	startedAt: string;
	state: "running" | "provider_blocked" | "awaiting_operator" | "hard_cap";
	providerBlocked: boolean;
	terminalReason: string;
	lastError?: ClassifiedProviderError;
	lastCompletedTool?: CompletedToolReference;
	retryAllowance?: { id: string; reason: string; issuedAt: string; consumedAt?: string; runtimeId?: string };
	/** A successful provider response establishes responsiveness only. */
	executionState: "unknown";
	cleanupState: "unknown";
}
export interface OutcomeEvent { schema: 1; sessionId: string; sequence: number; ts: string; kind: string; snapshot: ProviderOutcome }

const SUMMARY: Record<ProviderErrorCategory, string> = {
	provider_blocked: "Provider rejected this request under cybersecurity policy; operator action is required. No automatic retry or fallback.",
	authentication: "Provider authentication failed; credentials or access require operator review.",
	rate_limit: "Provider rate limit was reached; this is separate from a policy rejection.",
	network: "Provider transport failed; target execution and cleanup remain unknown.",
	provider_other: "Provider returned an unclassified error; inspect the original Pi error locally.",
};

function record(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
function identifier(value: unknown): string | undefined {
	if (typeof value !== "string" || !/^[A-Za-z0-9._:/|\-]{1,256}$/.test(value)) return undefined;
	return redactSecrets(value) === value ? value : undefined;
}

/** Inspect only finalized assistant errors. No prompt/content scanning and no
 * classification of ordinary assistant prose. Structured error codes outrank
 * the narrow historic Codex format; numeric HTTP status alone is not policy. */
export function classifyProviderError(message: unknown): ClassifiedProviderError | undefined {
	const m = record(message);
	if (m?.role !== "assistant" || m.stopReason !== "error") return undefined;
	const text = typeof m.errorMessage === "string" ? m.errorMessage : "";
	const codes = new Set<string>();
	for (const field of [m.error, m.providerError]) {
		const code = record(field)?.code;
		if (typeof code === "string" || typeof code === "number") codes.add(String(code).toLowerCase());
	}
	if (Array.isArray(m.diagnostics)) for (const diagnostic of m.diagnostics) {
		const code = record(record(diagnostic)?.error)?.code;
		if (typeof code === "string" || typeof code === "number") codes.add(String(code).toLowerCase());
	}
	// A serialized provider error is a structured object only when it parses as
	// a whole JSON value; mentioning a code in free text never grants semantics.
	try {
		const parsed = record(JSON.parse(text));
		const code = record(parsed?.error)?.code ?? parsed?.code;
		if (typeof code === "string" || typeof code === "number") codes.add(String(code).toLowerCase());
	} catch { /* Ordinary formatted errors are handled by the narrow matches below. */ }
	let category: ProviderErrorCategory = "provider_other";
	if (codes.has("cyber_policy") || /^Codex error: This content was flagged for possible cybersecurity risk\.(?:\s|$)/.test(text)) category = "provider_blocked";
	else if (["401", "invalid_api_key", "authentication_error", "unauthorized"].some(c => codes.has(c)) || /^(?:Codex error:\s*)?(?:authentication failed|unauthorized|invalid api key)\b/i.test(text)) category = "authentication";
	else if (["429", "rate_limit_exceeded", "rate_limit_error"].some(c => codes.has(c)) || /^(?:Codex error:\s*)?(?:rate limit|too many requests|429\b)/i.test(text)) category = "rate_limit";
	else if (["econnreset", "econnrefused", "etimedout", "enotfound", "eai_again"].some(c => codes.has(c)) || /^(?:Codex error:\s*)?(?:fetch failed|network error|connection reset|request timed out|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND)\b/i.test(text)) category = "network";
	return { category, summary: SUMMARY[category], provider: identifier(m.provider), model: identifier(m.model), requestId: identifier(m.requestId ?? m.request_id ?? record(m.responseHeaders)?.["x-request-id"]), responseId: identifier(m.responseId), fingerprint: createHash("sha256").update(text).digest("hex") };
}

export const outcomePath = (binding: OutcomeBinding): string => `${binding.sessionFile}.pluto-outcome.json`;
export const outcomeHistoryPath = (binding: OutcomeBinding): string => `${outcomePath(binding)}.events.jsonl`;

function validateOutcome(value: unknown, binding: OutcomeBinding): ProviderOutcome {
	const x = record(value);
	if (x?.schema !== 1 || x.sessionId !== binding.sessionId || !Number.isSafeInteger(x.sequence) || Number(x.sequence) < 0 || typeof x.updatedAt !== "string" || typeof x.startedAt !== "string" || !Number.isFinite(Date.parse(x.startedAt)) || typeof x.providerBlocked !== "boolean" || !["running", "provider_blocked", "awaiting_operator", "hard_cap"].includes(String(x.state)) || typeof x.terminalReason !== "string" || x.executionState !== "unknown" || x.cleanupState !== "unknown") throw new Error("Invalid or conflicting Pluto outcome descriptor; operator review required.");
	return x as unknown as ProviderOutcome;
}

export function readOutcome(binding: OutcomeBinding): ProviderOutcome | undefined {
	let current: ProviderOutcome | undefined;
	if (existsSync(outcomePath(binding))) current = validateOutcome(JSON.parse(readFileSync(outcomePath(binding), "utf8")), binding);
	if (existsSync(outcomeHistoryPath(binding))) {
		const lines = readFileSync(outcomeHistoryPath(binding), "utf8").split("\n");
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (!line) continue;
			let event: OutcomeEvent;
			try { event = JSON.parse(line) as OutcomeEvent; } catch {
				// A torn append might contain an interruption not yet projected.
				// Never discard it and silently resume; fail closed for review.
				throw new Error("Corrupt Pluto outcome history; operator review required.");
			}
			const snapshot = validateOutcome(event.snapshot, binding);
			if (event.sessionId !== binding.sessionId || event.sequence !== snapshot.sequence) throw new Error("Conflicting Pluto outcome history.");
			if (!current || snapshot.sequence > current.sequence) current = snapshot;
		}
	}
	return current;
}

function initial(binding: OutcomeBinding, now: string): ProviderOutcome {
	return { schema: 1, sessionId: binding.sessionId, sequence: 0, updatedAt: now, startedAt: now, state: "running", providerBlocked: false, terminalReason: "in_progress", executionState: "unknown", cleanupState: "unknown" };
}

function syncDirectory(path: string): void {
	const fd = openSync(dirname(path), "r");
	try { fsyncSync(fd); } finally { closeSync(fd); }
}

/** Synchronous persistence lets message_end abort synchronously and record the
 * stop before any later retry/settlement hook. It preserves original messages. */
function mutate(binding: OutcomeBinding, kind: string, update: (state: ProviderOutcome) => void): ProviderOutcome {
	const now = new Date().toISOString();
	const next = structuredClone(readOutcome(binding) ?? initial(binding, now));
	update(next);
	next.sequence += 1;
	next.updatedAt = now;
	const event: OutcomeEvent = { schema: 1, sessionId: binding.sessionId, sequence: next.sequence, ts: now, kind, snapshot: next };
	const history = openSync(outcomeHistoryPath(binding), "a", 0o600);
	try { appendFileSync(history, `${JSON.stringify(event)}\n`, "utf8"); fsyncSync(history); } finally { closeSync(history); }
	syncDirectory(outcomeHistoryPath(binding));
	const temp = `${outcomePath(binding)}.${randomUUID()}.tmp`;
	const fd = openSync(temp, "wx", 0o600);
	try { writeFileSync(fd, JSON.stringify(next, null, 2)); fsyncSync(fd); } finally { closeSync(fd); }
	try { renameSync(temp, outcomePath(binding)); syncDirectory(outcomePath(binding)); } catch (error) {
		try { unlinkSync(temp); } catch { /* Original write failure remains visible. */ }
		throw error;
	}
	return next;
}

export function initializeOutcome(binding: OutcomeBinding, inherited?: ProviderOutcome): ProviderOutcome {
	return readOutcome(binding) ?? mutate(binding, "run_initialized", s => {
		if (!inherited) return;
		s.startedAt = inherited.startedAt;
		s.providerBlocked = inherited.providerBlocked;
		s.lastError = inherited.lastError;
		s.state = inherited.state === "hard_cap" ? "hard_cap" : inherited.providerBlocked ? "provider_blocked" : "awaiting_operator";
		s.terminalReason = inherited.terminalReason;
		// Tool references may belong to the parent's session. Do not mislabel
		// them as child execution or carry its one-shot retry grant.
	});
}
export function recordProviderError(binding: OutcomeBinding, error: ClassifiedProviderError): ProviderOutcome {
	return mutate(binding, "provider_error", s => {
		s.lastError = error;
		delete s.retryAllowance;
		if (error.category === "provider_blocked") s.providerBlocked = true;
		if (s.state !== "hard_cap") { s.state = s.providerBlocked ? "provider_blocked" : "awaiting_operator"; s.terminalReason = error.category; }
	});
}
export function recordCompletedTool(binding: OutcomeBinding, ref: CompletedToolReference): ProviderOutcome {
	return mutate(binding, "tool_completed", s => {
		s.lastCompletedTool = { toolCallId: identifier(ref.toolCallId) ?? "unavailable", toolName: identifier(ref.toolName) ?? "unavailable", completedAt: ref.completedAt, isError: ref.isError };
	});
}
export function recordHardCap(binding: OutcomeBinding, reason: string): ProviderOutcome {
	if (!/^hard_cap:(wall_clock|tool_calls|tokens)$/.test(reason)) throw new Error("Invalid hard cap reason.");
	return mutate(binding, "hard_cap", s => { s.state = "hard_cap"; s.terminalReason = reason; delete s.retryAllowance; });
}
export function recordLocalInterruption(binding: OutcomeBinding, reason: "scope_denied" | "environment_paused"): ProviderOutcome {
	return mutate(binding, reason, s => { if (s.state !== "hard_cap" && !s.providerBlocked) { s.state = "awaiting_operator"; s.terminalReason = reason; } });
}
export function settleOutcome(binding: OutcomeBinding): ProviderOutcome {
	return mutate(binding, "turn_settled", s => {
		delete s.retryAllowance;
		if (s.state !== "hard_cap") { s.state = s.providerBlocked ? "provider_blocked" : "awaiting_operator"; s.terminalReason = s.providerBlocked ? "provider_blocked" : s.lastError ? s.lastError.category : ["scope_denied", "environment_paused"].includes(s.terminalReason) ? s.terminalReason : "awaiting_operator"; }
	});
}
export function requestProviderRetry(binding: OutcomeBinding, reason: string): ProviderOutcome {
	const clean = redactSecrets(reason.trim()).replace(/[\r\n\t]/g, " ").slice(0, 240);
	if (!clean || clean === "[REDACTED]") throw new Error("State the operator's reason for this one-request retry.");
	return mutate(binding, "operator_retry_requested", s => {
		if (s.state === "hard_cap") throw new Error("A provider retry cannot clear a deterministic hard cap.");
		if (!s.providerBlocked) throw new Error("No policy interruption is awaiting an operator retry.");
		s.retryAllowance = { id: randomUUID(), reason: clean, issuedAt: new Date().toISOString() };
	});
}
export function consumeProviderRetry(binding: OutcomeBinding, runtimeId: string): boolean {
	const state = readOutcome(binding);
	if (!state?.providerBlocked || !state.retryAllowance || state.retryAllowance.consumedAt || state.state === "hard_cap") return false;
	mutate(binding, "operator_retry_started", s => { if (s.retryAllowance) { s.retryAllowance.consumedAt = new Date().toISOString(); s.retryAllowance.runtimeId = runtimeId; } });
	return true;
}
export function retryIsActive(binding: OutcomeBinding, runtimeId: string): boolean {
	const s = readOutcome(binding);
	return s?.state !== "hard_cap" && Boolean(s?.retryAllowance?.consumedAt && s.retryAllowance.runtimeId === runtimeId);
}
export function recordProviderRecovery(binding: OutcomeBinding, runtimeId: string): ProviderOutcome | undefined {
	const prior = readOutcome(binding);
	if (!prior || prior.state === "hard_cap" || !prior.lastError || (prior.providerBlocked && !retryIsActive(binding, runtimeId))) return prior;
	return mutate(binding, "provider_recovered", s => { s.providerBlocked = false; s.state = "running"; s.terminalReason = "in_progress"; delete s.lastError; delete s.retryAllowance; });
}
/** Children never consume the parent's retry. They remain held while its
 * provider is blocked; only the parent's deliberate operator request can run. */
export function getProviderHold(binding: OutcomeBinding): { blocked: boolean; reason: string } {
	const s = readOutcome(binding);
	return { blocked: Boolean(s?.providerBlocked || s?.state === "hard_cap"), reason: s?.state === "hard_cap" ? s.terminalReason : s?.providerBlocked ? "provider_blocked" : s?.terminalReason ?? "in_progress" };
}
