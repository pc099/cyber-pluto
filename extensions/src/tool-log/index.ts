/**
 * tool-log: logs every tool invocation Pi's reasoning core makes, in full,
 * before and after execution.
 *
 * This is the Session 1 stand-in for the Architecture §4 `attempts` table
 * (that's Session 2's SQLite schema). Until then, this is the audit trail —
 * per the pluto-build invariant "everything is logged", nothing runs through
 * the tool layer unrecorded, from day one.
 *
 * Two lines are written per invocation, correlated by toolCallId, rather than
 * one line on completion: a "tool_call" record lands before the tool runs, so
 * an attempt is on the record even if the process dies mid-execution.
 */
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
	ToolExecutionEndEvent,
} from "@earendil-works/pi-coding-agent";

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
	const line = `${JSON.stringify(entry)}\n`;
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
	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
		await appendLogEntry(ctx.cwd, {
			phase: "tool_call",
			ts: new Date().toISOString(),
			sessionId: ctx.sessionManager.getSessionId(),
			toolCallId: event.toolCallId,
			toolName: event.toolName,
			input: event.input,
		});
	});

	pi.on("tool_execution_end", async (event: ToolExecutionEndEvent, ctx: ExtensionContext) => {
		await appendLogEntry(ctx.cwd, {
			phase: "tool_execution_end",
			ts: new Date().toISOString(),
			sessionId: ctx.sessionManager.getSessionId(),
			toolCallId: event.toolCallId,
			toolName: event.toolName,
			isError: event.isError,
			result: event.result,
		});
	});
}
