/**
 * Bridges Pi's tool_call/tool_execution_end events to real `attempts` rows
 * in the Layer 2 state DB (Architecture §4.3), alongside the raw JSONL
 * capture in index.ts. This is Session 2's structured, queryable half of
 * the audit trail; the JSONL file remains the crash-safe raw half.
 *
 * Engagement bootstrap (opening the DB, creating the target + root node)
 * lives in ../state/engagement.ts, shared with the recon extension so both
 * operate against the same target/tree rather than each creating their own.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parseBaseTool } from "../shared/bash-command.js";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { attackTagForCommand } from "./attack-mapping.js";

export { startEngagement };

const EVIDENCE_DIR = "evidence/attempts";

const pendingAttemptIds = new Map<string, number>();

function toolAndCommandFor(toolName: string, input: unknown): { tool: string; command: string } {
	if (toolName === "bash" && input && typeof input === "object" && "command" in input) {
		const command = String((input as { command: unknown }).command);
		return { tool: parseBaseTool(command) ?? "bash", command };
	}
	return { tool: toolName, command: JSON.stringify(input) };
}

export function recordAttemptStart(toolCallId: string, toolName: string, input: unknown): void {
	const engagement = getEngagement();
	if (!engagement) {
		console.error("[pluto/tool-log] no engagement DB open; skipping attempts row (JSONL log still covers this call)");
		return;
	}
	const { tool, command } = toolAndCommandFor(toolName, input);
	const tag = toolName === "bash" ? attackTagForCommand(command) : undefined;
	const attempt = engagement.repos.attempts.start({
		targetId: engagement.targetId,
		nodeId: engagement.rootNodeId,
		tool,
		command,
		tactic: tag?.tactic,
		technique: tag?.technique,
	});
	pendingAttemptIds.set(toolCallId, attempt.id);
}

export async function recordAttemptEnd(
	cwd: string,
	toolCallId: string,
	isError: boolean,
	result: unknown,
): Promise<void> {
	const engagement = getEngagement();
	if (!engagement) {
		return;
	}
	const attemptId = pendingAttemptIds.get(toolCallId);
	if (attemptId === undefined) {
		return;
	}
	pendingAttemptIds.delete(toolCallId);

	let outputRef: string | null = null;
	try {
		outputRef = await writeOutputEvidence(cwd, attemptId, result);
	} catch (error) {
		console.error("[pluto/tool-log] failed to write output evidence for attempt", attemptId, error);
	}
	engagement.repos.attempts.finish(attemptId, {
		outcome: isError ? "failure" : "success",
		outputRef,
	});
}

async function writeOutputEvidence(cwd: string, attemptId: number, result: unknown): Promise<string> {
	const relPath = join(EVIDENCE_DIR, `${attemptId}.json`);
	const absPath = join(cwd, relPath);
	await mkdir(dirname(absPath), { recursive: true });
	await writeFile(absPath, JSON.stringify(result, null, 2), "utf8");
	return relPath;
}
