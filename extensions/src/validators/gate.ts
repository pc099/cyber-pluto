/**
 * Shared Gate 1 glue used by every class validator: capture evidence → write
 * the `validations` row → drive the status-guarded promote/reject in
 * findings-repo. Written once so no class can accidentally skip the gate or the
 * evidence trail, and so the candidate→validated transition always flows
 * through the single enforcement point (findings-repo.promote).
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AgentToolResult } from "@earendil-works/pi-coding-agent";
import type { Engagement } from "../state/engagement.js";
import { IllegalStatusTransition } from "../state/findings-repo.js";
import type { CapturedExchange, VerifiableStep } from "./report.js";

const EVIDENCE_DIR = "evidence/validations";

export interface GateReport {
	validator: string;
	passed: boolean;
	diffSummary: string;
	baseline: CapturedExchange | null;
	attacks: CapturedExchange[];
	steps: VerifiableStep[];
}

async function writeEvidence(cwd: string, findingId: number, report: GateReport): Promise<{ baselineRef: string; attackRef: string }> {
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	const relDir = join(EVIDENCE_DIR, `finding-${findingId}-${report.validator}-${stamp}`);
	await mkdir(join(cwd, relDir), { recursive: true });
	const baselineRef = join(relDir, "baseline.json");
	const attackRef = join(relDir, "attacks.json");
	await writeFile(join(cwd, baselineRef), JSON.stringify(report.baseline, null, 2), "utf8");
	await writeFile(
		join(cwd, attackRef),
		JSON.stringify({ steps: report.steps, attacks: report.attacks, diffSummary: report.diffSummary }, null, 2),
		"utf8",
	);
	return { baselineRef, attackRef };
}

function renderSteps(report: GateReport): string {
	return report.steps.map((s) => `  [${s.passed ? "✓" : "✗"}] ${s.name}: ${s.detail}`).join("\n");
}

/** Record evidence + a validations row, then promote or reject the finding
 * through the status guard. Returns the tool result to hand back to the model. */
export async function recordAndGate(
	cwd: string,
	engagement: Engagement,
	findingId: number,
	report: GateReport,
): Promise<AgentToolResult<unknown>> {
	const { baselineRef, attackRef } = await writeEvidence(cwd, findingId, report);
	const validation = engagement.repos.validations.create({
		findingId,
		validator: report.validator,
		baselineRef,
		attackRef,
		diffSummary: report.diffSummary,
		passed: report.passed,
	});

	try {
		const updated = report.passed
			? engagement.repos.findings.promote(findingId, validation.id)
			: engagement.repos.findings.reject(findingId);
		const verdict = report.passed ? "VALIDATED" : "REJECTED";
		return {
			content: [
				{
					type: "text",
					text:
						`Gate 1 [${report.validator}] ${verdict} — finding #${findingId} is now '${updated.status}'.\n` +
						`validations row #${validation.id} (passed=${report.passed ? 1 : 0})\n` +
						`${report.diffSummary}\n` +
						`Verifiable steps:\n${renderSteps(report)}\n` +
						`Evidence: ${baselineRef}, ${attackRef}`,
				},
			],
			details: { validationId: validation.id, passed: report.passed, status: updated.status },
		};
	} catch (err) {
		if (err instanceof IllegalStatusTransition) {
			return {
				content: [
					{
						type: "text",
						text: `Validation recorded (#${validation.id}, passed=${report.passed}) but the status transition was refused: ${err.message}`,
					},
				],
				details: { validationId: validation.id, passed: report.passed },
			};
		}
		throw err;
	}
}
