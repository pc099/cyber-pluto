/**
 * validators: the Gate 1 extension (Architecture §3.1, §4.4, §4.5).
 *
 * Exposes two tools to the reasoning core, deliberately split to keep the
 * "propose" and "confirm" roles distinct (§4.5 — the reasoning that got
 * excited about a finding is not the reasoning that gets to confirm it):
 *   - record_sqli_candidate: files a suspected SQLi as a `candidate` finding.
 *   - validate_sqli: runs the DETERMINISTIC validator (../validators/sqli.ts)
 *     against the injection point, records a `validations` row, and — via the
 *     status-guarded findings-repo — promotes the candidate to `validated`
 *     only if the validator reproduced it, else rejects it.
 *
 * The reasoning core supplies only the injection point. It never supplies the
 * verdict: `passed` comes solely from the deterministic code path, and the
 * candidate→validated transition is gated in findings-repo, so no LLM output
 * can fabricate a validated finding. Full process-level role separation (a
 * distinct validator sub-agent) is Session 9; here the separation is
 * structural — the gate is code, not judgment.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AgentToolResult, ExtensionAPI, ExtensionContext, SessionStartEvent } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { IllegalStatusTransition } from "../state/findings-repo.js";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { type SqliValidationReport, validateSqli } from "./sqli.js";

const EVIDENCE_DIR = "evidence/validations";

function portForEndpoint(endpoint: string): { port: number | null; service: string } {
	try {
		const url = new URL(endpoint);
		const service = url.protocol === "https:" ? "https" : "http";
		const port = url.port ? Number(url.port) : service === "https" ? 443 : 80;
		return { port, service };
	} catch {
		return { port: null, service: "http" };
	}
}

async function writeEvidence(
	cwd: string,
	findingId: number,
	report: SqliValidationReport,
): Promise<{ baselineRef: string; attackRef: string }> {
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	const relDir = join(EVIDENCE_DIR, `finding-${findingId}-${stamp}`);
	const absDir = join(cwd, relDir);
	await mkdir(absDir, { recursive: true });

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

function renderSteps(report: SqliValidationReport): string {
	return report.steps.map((s) => `  [${s.passed ? "✓" : "✗"}] ${s.name}: ${s.detail}`).join("\n");
}

export default function validatorsExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.registerTool({
		name: "record_sqli_candidate",
		label: "Record SQLi Candidate",
		description:
			"File a suspected SQL-injection point as a CANDIDATE finding (unconfirmed). Returns the finding id to pass to validate_sqli. This only records a hypothesis — it does not confirm anything.",
		parameters: Type.Object({
			endpoint: Type.String({ description: "Full endpoint URL, e.g. http://127.0.0.1:8888/item" }),
			note: Type.Optional(Type.String({ description: "Why you suspect SQLi here" })),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx): Promise<AgentToolResult<unknown>> {
			const engagement = getEngagement();
			if (!engagement) {
				return { content: [{ type: "text", text: "No engagement state DB is open." }], details: {} };
			}
			const { port, service } = portForEndpoint(params.endpoint);
			const finding = engagement.repos.findings.create({
				targetId: engagement.targetId,
				nodeId: engagement.rootNodeId,
				port,
				protocol: "tcp",
				service,
				confidence: 0.3,
			});
			return {
				content: [
					{
						type: "text",
						text: `Recorded candidate finding #${finding.id} (status: candidate) for ${params.endpoint}. Confirm it with validate_sqli.`,
					},
				],
				details: { findingId: finding.id },
			};
		},
	});

	pi.registerTool({
		name: "validate_sqli",
		label: "Validate SQLi (Gate 1)",
		description:
			"Run Pluto's deterministic, non-LLM Gate 1 SQL-injection validator against a candidate finding: it sends fixed baseline/attack probes, checks for a database-error or boolean differential (technical signal) AND a UNION-reflected marker (impact artifact), then promotes the finding to 'validated' if reproduced or 'rejected' if not. You do not decide the verdict — the validator does.",
		parameters: Type.Object({
			finding_id: Type.Number({ description: "Candidate finding id from record_sqli_candidate" }),
			endpoint: Type.String({ description: "Full endpoint URL, e.g. http://127.0.0.1:8888/item" }),
			param: Type.String({ description: "The query parameter to inject, e.g. id" }),
			baseline_value: Type.String({ description: "A known-good value for that parameter, e.g. 1" }),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const engagement = getEngagement();
			if (!engagement) {
				return { content: [{ type: "text", text: "No engagement state DB is open." }], details: {} };
			}
			const finding = engagement.repos.findings.getById(params.finding_id);
			if (!finding) {
				return {
					content: [{ type: "text", text: `No finding #${params.finding_id} exists. Record it first with record_sqli_candidate.` }],
					details: {},
				};
			}

			const report = await validateSqli({
				endpoint: params.endpoint,
				param: params.param,
				baselineValue: params.baseline_value,
			});
			const { baselineRef, attackRef } = await writeEvidence(ctx.cwd, params.finding_id, report);

			const validation = engagement.repos.validations.create({
				findingId: params.finding_id,
				validator: "sqli",
				baselineRef,
				attackRef,
				diffSummary: report.diffSummary,
				passed: report.passed,
			});

			let newStatus: string;
			try {
				const updated = report.passed
					? engagement.repos.findings.promote(params.finding_id, validation.id)
					: engagement.repos.findings.reject(params.finding_id);
				newStatus = updated.status;
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

			const verdict = report.passed ? "VALIDATED" : "REJECTED";
			return {
				content: [
					{
						type: "text",
						text:
							`Gate 1 ${verdict} — finding #${params.finding_id} is now '${newStatus}'.\n` +
							`validations row #${validation.id} (passed=${report.passed ? 1 : 0})\n` +
							`${report.diffSummary}\n` +
							`Verifiable steps:\n${renderSteps(report)}\n` +
							`Evidence: ${baselineRef}, ${attackRef}`,
					},
				],
				details: { validationId: validation.id, passed: report.passed, status: newStatus },
			};
		},
	});
}
