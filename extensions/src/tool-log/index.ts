/**
 * tool-log: logs every tool invocation Pi's reasoning core makes, in full,
 * before and after execution — twice over.
 *
 * 1. A raw JSONL line per phase (tool_call / tool_execution_end), correlated
 *    by toolCallId, in logs/tool-invocations.jsonl — the Session 1 crash-safe
 *    capture: an attempt is on record even if the process dies mid-execution.
 * 2. A real `attempts` row in the Layer 2 state DB (Architecture §4.3, see
 *    attempts-recorder.ts) — the Session 2 structured, queryable half, with
 *    an ATT&CK tag where one applies (§5.4).
 *
 * Per the pluto-build invariant "everything is logged," nothing reaches the
 * tool layer unrecorded, from day one.
 */
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
	ToolCallEvent,
	ToolExecutionEndEvent,
} from "@earendil-works/pi-coding-agent";
import { capField, redactSecrets } from "../shared/redact.js";
import { knownSecrets, recordAttemptEnd, recordAttemptStart, startEngagement } from "./attempts-recorder.js";

const LOG_DIR = "logs";
const LOG_FILE = "tool-invocations.jsonl";

interface ToolCallLogEntry {
	phase: "tool_call";
	ts: string;
	sessionId: string | undefined;
	toolCallId: string;
	toolName: string;
	input: unknown;
}

interface ToolExecutionEndLogEntry {
	phase: "tool_execution_end";
	ts: string;
	sessionId: string | undefined;
	toolCallId: string;
	toolName: string;
	isError: boolean;
	result: unknown;
}

type ToolLogEntry = ToolCallLogEntry | ToolExecutionEndLogEntry;

async function appendLogEntry(cwd: string, entry: ToolLogEntry): Promise<void> {
	const dir = join(cwd, LOG_DIR);
	const file = join(dir, LOG_FILE);
	// Mask secrets (private keys, tokens, passwords, recovered credentials)
	// before this reaches disk — "everything is logged" must not mean "every
	// secret is logged in the clear". The oversized field was already capped by
	// the caller (capField) so the serialized line stays valid JSON.
	const line = `${redactSecrets(JSON.stringify(entry), knownSecrets())}\n`;
	try {
		await mkdir(dir, { recursive: true });
		await appendFile(file, line, "utf8");
	} catch (error) {
		// Logging is not optional (pluto-build skill). Never swallow a logging
		// failure silently: surface the full record on stderr so the gap in the
		// audit trail is visible even when the write itself failed.
		console.error("[pluto/tool-log] failed to write invocation log:", error);
		console.error("[pluto/tool-log] lost entry:", line);
	}
}

export default function toolLogExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
		recordAttemptStart(event.toolCallId, event.toolName, event.input);
		await appendLogEntry(ctx.cwd, {
			phase: "tool_call",
			ts: new Date().toISOString(),
			sessionId: ctx.sessionManager.getSessionId(),
			toolCallId: event.toolCallId,
			toolName: event.toolName,
			input: capField(event.input),
		});
	});

	pi.on("tool_execution_end", async (event: ToolExecutionEndEvent, ctx: ExtensionContext) => {
		await recordAttemptEnd(ctx.cwd, event.toolCallId, event.isError, event.result);
		await appendLogEntry(ctx.cwd, {
			phase: "tool_execution_end",
			ts: new Date().toISOString(),
			sessionId: ctx.sessionManager.getSessionId(),
			toolCallId: event.toolCallId,
			toolName: event.toolName,
			isError: event.isError,
			result: capField(event.result),
		});
	});
}
