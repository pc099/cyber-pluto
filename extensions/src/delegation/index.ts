/**
 * delegation: the §6.4 agent-handoff extension, modeled on CAI's two modes.
 *
 *  - delegate_handoff  (full handoff): a specialist sub-agent owns a
 *    self-contained sub-task end-to-end and reports back only when done —
 *    e.g. an exploitation specialist taking a validated finding to a PoC.
 *  - consult_specialist (agent-as-tool): a bounded consultation that returns
 *    an answer without ceding control — the lead keeps the overall view of the
 *    engagement (e.g. a CVE breakdown).
 *
 * Each delegation is logged like any tool invocation (§6.4): an attempts row
 * records which sub-agent, which mode, and the full returned output is retained
 * as evidence, plus a line in logs/delegations.jsonl. Every sub-agent is
 * spawned with the red-lines gate loaded (see spawn.ts) — the §10.4 check
 * propagates into every delegated agent (the Session 5 contract), verifiable
 * because a red-lined action inside a sub-agent is blocked by that sub-agent's
 * own pre-execution check.
 */
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AgentToolResult, ExtensionAPI, ExtensionContext, SessionStartEvent } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { spawnSubAgent } from "./spawn.js";

const EVIDENCE_DIR = "evidence/delegations";
const LOG_DIR = "logs";
const LOG_FILE = "delegations.jsonl";

async function logDelegation(
	cwd: string,
	mode: string,
	run: { specialist: string; extensions: string[]; provider?: string; model: string; output: string },
	attemptId: number | undefined,
): Promise<string> {
	// Retain the full sub-agent output as evidence.
	const rel = join(EVIDENCE_DIR, `delegation-${attemptId ?? Date.now()}.txt`);
	try {
		await mkdir(join(cwd, EVIDENCE_DIR), { recursive: true });
		await writeFile(join(cwd, rel), run.output, "utf8");
	} catch (err) {
		console.error("[pluto/delegation] failed to write delegation evidence:", err);
	}
	// A structured audit line: which sub-agent, which mode, what came back (§6.4).
	try {
		await mkdir(join(cwd, LOG_DIR), { recursive: true });
		await appendFile(
			join(cwd, LOG_DIR, LOG_FILE),
			`${JSON.stringify({
				ts: new Date().toISOString(),
				mode,
				specialist: run.specialist,
				provider: run.provider,
				model: run.model,
				extensions: run.extensions,
				attemptId,
				outputPreview: run.output.slice(0, 500),
			})}\n`,
			"utf8",
		);
	} catch (err) {
		console.error("[pluto/delegation] failed to write delegation log:", err);
	}
	return rel;
}

function recordAttempt(mode: string, specialist: string, summary: string): number | undefined {
	const engagement = getEngagement();
	if (!engagement) return undefined;
	const attempt = engagement.repos.attempts.start({
		targetId: engagement.targetId,
		nodeId: engagement.rootNodeId,
		tool: `delegate:${mode}`,
		command: `${specialist}: ${summary}`.slice(0, 500),
	});
	return attempt.id;
}

function finishAttempt(attemptId: number | undefined, outputRef: string, note: string): void {
	const engagement = getEngagement();
	if (!engagement || attemptId === undefined) return;
	engagement.repos.attempts.finish(attemptId, { outcome: "success", outputRef, reasoningNote: note });
}

export default function delegationExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.registerTool({
		name: "consult_specialist",
		label: "Consult Specialist (agent-as-tool)",
		description:
			"Agent-as-tool delegation (§6.4): spawn a bounded specialist sub-agent to answer a focused question and return its answer WITHOUT ceding control of the engagement. Use for quick consultations (a CVE breakdown, an analysis) where you stay in charge. The sub-agent runs in its own isolated context with the red-lines gate.",
		parameters: Type.Object({
			question: Type.String({ description: "The focused question for the specialist" }),
			specialist: Type.Optional(Type.String({ description: "analyst (default) | recon | exploitation" })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const specialist = params.specialist ?? "analyst";
			const attemptId = recordAttempt("agent_as_tool", specialist, params.question);
			let run;
			try {
				run = await spawnSubAgent(ctx.cwd, {
					specialist,
					prompt:
						`You are a ${specialist} consultant being consulted as a tool. Answer this focused question concisely and return the answer only; you do not control the engagement. Question: ${params.question}`,
				});
			} catch (err) {
				return {
					content: [{ type: "text", text: `Consultation failed: ${err instanceof Error ? err.message : String(err)}` }],
					details: { attemptId },
				};
			}
			const outputRef = await logDelegation(ctx.cwd, "agent_as_tool", run, attemptId);
			finishAttempt(attemptId, outputRef, `agent-as-tool consult of ${specialist}`);
			return {
				content: [{ type: "text", text: `Specialist (${specialist}) answered:\n\n${run.output}` }],
				details: { attemptId, mode: "agent_as_tool", specialist, outputRef },
			};
		},
	});

	pi.registerTool({
		name: "delegate_handoff",
		label: "Delegate (full handoff)",
		description:
			"Full-handoff delegation (§6.4): hand a self-contained sub-task to a specialist sub-agent that owns it end-to-end and reports back only when done — e.g. an exploitation specialist taking a validated finding to a PoC. Control passes to the sub-agent for the sub-task. The sub-agent runs in its own isolated context with the red-lines gate and shares the engagement state.",
		parameters: Type.Object({
			task: Type.String({ description: "The self-contained sub-task to hand off" }),
			specialist: Type.String({ description: "exploitation | recon | analyst" }),
			finding_id: Type.Optional(Type.Number({ description: "Relevant finding id, if any" })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const context = params.finding_id ? ` The relevant finding id is ${params.finding_id}.` : "";
			const attemptId = recordAttempt("handoff", params.specialist, params.task);
			let run;
			try {
				run = await spawnSubAgent(ctx.cwd, {
					specialist: params.specialist,
					prompt:
						`You are a ${params.specialist} specialist. You have been handed this self-contained sub-task and own it end to end; use your tools, then report back what you did and the outcome.${context} Sub-task: ${params.task}`,
				});
			} catch (err) {
				return {
					content: [{ type: "text", text: `Handoff failed: ${err instanceof Error ? err.message : String(err)}` }],
					details: { attemptId },
				};
			}
			const outputRef = await logDelegation(ctx.cwd, "handoff", run, attemptId);
			finishAttempt(attemptId, outputRef, `full handoff to ${params.specialist}`);
			return {
				content: [{ type: "text", text: `Specialist (${params.specialist}) completed the handoff and reported:\n\n${run.output}` }],
				details: { attemptId, mode: "handoff", specialist: params.specialist, outputRef },
			};
		},
	});
}
