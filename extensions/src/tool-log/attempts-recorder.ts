/**
 * Bridges Pi's tool_call/tool_execution_end events to real `attempts` rows
 * in the Layer 2 state DB (Architecture §4.3), alongside the raw JSONL
 * capture in jsonl-log.ts. This is Session 2's structured, queryable half
 * of the audit trail; the JSONL file remains the crash-safe raw half.
 *
 * Deliberately simple for Session 2: one target + one root recon node are
 * created fresh per Pi session, with no reuse or per-service branching.
 * Growing a real investigation tree from decisions is Session 3's feedback
 * loop, not this module's job.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { attackTagForCommand, parseBaseTool } from "./attack-mapping.js";
import type { AttemptsRepo } from "../state/attempts-repo.js";
import { createAttemptsRepo } from "../state/attempts-repo.js";
import { openStateDb } from "../state/db.js";
import { createNodesRepo } from "../state/nodes-repo.js";
import { createTargetsRepo } from "../state/targets-repo.js";

const EVIDENCE_DIR = "evidence/attempts";

interface Engagement {
	db: DatabaseSync;
	targetId: number;
	rootNodeId: number;
	attemptsRepo: AttemptsRepo;
}

let engagement: Engagement | undefined;
const pendingAttemptIds = new Map<string, number>();

export function startEngagement(cwd: string): void {
	const db = openStateDb(cwd);
	const targetsRepo = createTargetsRepo(db);
	const nodesRepo = createNodesRepo(db);
	const attemptsRepo = createAttemptsRepo(db);

	const target = targetsRepo.create({
		label: process.env["PLUTO_TARGET_LABEL"] ?? "ad-hoc",
		host: process.env["PLUTO_TARGET_HOST"] ?? "localhost",
	});
	const rootNode = nodesRepo.create({
		targetId: target.id,
		nodeType: "recon",
		label: "session root",
	});

	engagement = { db, targetId: target.id, rootNodeId: rootNode.id, attemptsRepo };
}

function toolAndCommandFor(toolName: string, input: unknown): { tool: string; command: string } {
	if (toolName === "bash" && input && typeof input === "object" && "command" in input) {
		const command = String((input as { command: unknown }).command);
		return { tool: parseBaseTool(command) ?? "bash", command };
	}
	return { tool: toolName, command: JSON.stringify(input) };
}

export function recordAttemptStart(toolCallId: string, toolName: string, input: unknown): void {
	if (!engagement) {
		console.error("[pluto/tool-log] no engagement DB open; skipping attempts row (JSONL log still covers this call)");
		return;
	}
	const { tool, command } = toolAndCommandFor(toolName, input);
	const tag = toolName === "bash" ? attackTagForCommand(command) : undefined;
	const attempt = engagement.attemptsRepo.start({
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
	engagement.attemptsRepo.finish(attemptId, {
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
