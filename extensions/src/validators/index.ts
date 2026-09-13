/**
 * validators: the Gate 1 extension (Architecture §3.1, §3.5, §4.4, §4.5).
 *
 * `record_candidate` files a suspected finding as `candidate`; a per-class
 * `validate_*` tool runs the matching DETERMINISTIC, non-LLM validator and,
 * through the shared gate glue (gate.ts → the status-guarded findings-repo),
 * promotes it to `validated` only if reproduced, else `rejected`.
 *
 * Propose and confirm are kept distinct (§4.5 — the reasoning that got excited
 * about a finding is not the reasoning that gets to confirm it): the reasoning
 * core supplies only the injection point, never the verdict. `passed` comes
 * solely from the deterministic code, and candidate→validated is gated in
 * findings-repo, so no LLM output can fabricate a validated finding.
 */
import type { AgentToolResult, ExtensionAPI, ExtensionContext, SessionStartEvent } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { type Engagement, getEngagement, startEngagement } from "../state/engagement.js";
import { type FindingRow } from "../state/types.js";
import { validateCommandInjection } from "./command-injection.js";
import { type GateReport, recordAndGate } from "./gate.js";
import { validatePathTraversal } from "./path-traversal.js";
import { validateSqli } from "./sqli.js";
import { validateXss } from "./xss.js";

function portForEndpoint(endpoint: string): { port: number | null; service: string } {
	try {
		const url = new URL(endpoint);
		const service = url.protocol === "https:" ? "https" : "http";
		return { port: url.port ? Number(url.port) : service === "https" ? 443 : 80, service };
	} catch {
		return { port: null, service: "http" };
	}
}

/** Load the finding and confirm an engagement is open — shared by every
 * validate_* tool. Returns either the pair or a ready-to-return error result. */
function loadFinding(
	findingId: number,
): { engagement: Engagement; finding: FindingRow } | AgentToolResult<unknown> {
	const engagement = getEngagement();
	if (!engagement) {
		return { content: [{ type: "text", text: "No engagement state DB is open." }], details: {} };
	}
	const finding = engagement.repos.findings.getById(findingId);
	if (!finding) {
		return {
			content: [{ type: "text", text: `No finding #${findingId} exists. Record it first with record_candidate.` }],
			details: {},
		};
	}
	return { engagement, finding };
}

function isResult(x: unknown): x is AgentToolResult<unknown> {
	return typeof x === "object" && x !== null && "content" in x;
}

const injectionParams = {
	finding_id: Type.Number({ description: "Candidate finding id from record_candidate" }),
	endpoint: Type.String({ description: "Full endpoint URL, e.g. http://127.0.0.1:8891/ping" }),
	param: Type.String({ description: "The query parameter to inject, e.g. host" }),
	baseline_value: Type.String({ description: "A known-good value for that parameter" }),
};

export default function validatorsExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.registerTool({
		name: "record_candidate",
		label: "Record Candidate Finding",
		description:
			"File a suspected web vulnerability as a CANDIDATE finding (unconfirmed). Returns the finding id to pass to the matching validate_* tool. Records a hypothesis only — it confirms nothing.",
		parameters: Type.Object({
			endpoint: Type.String({ description: "Full endpoint URL" }),
			vuln_class: Type.Optional(Type.String({ description: "sqli | command_injection | path_traversal | xss | ..." })),
			note: Type.Optional(Type.String({ description: "Why you suspect it" })),
		}),
		async execute(_id, params): Promise<AgentToolResult<unknown>> {
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
				product: params.vuln_class ?? null,
				confidence: 0.3,
			});
			return {
				content: [
					{ type: "text", text: `Recorded candidate finding #${finding.id} (candidate) for ${params.endpoint}. Confirm it with the matching validate_* tool.` },
				],
				details: { findingId: finding.id },
			};
		},
	});

	function registerValidator(
		name: string,
		description: string,
		run: (t: { endpoint: string; param: string; baselineValue: string }) => Promise<GateReport>,
	): void {
		pi.registerTool({
			name,
			label: `Validate ${name.replace("validate_", "")} (Gate 1)`,
			description,
			parameters: Type.Object(injectionParams),
			async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
				const loaded = loadFinding(params.finding_id);
				if (isResult(loaded)) return loaded;
				const report = await run({
					endpoint: params.endpoint,
					param: params.param,
					baselineValue: params.baseline_value,
				});
				return recordAndGate(ctx.cwd, loaded.engagement, params.finding_id, report);
			},
		});
	}

	registerValidator(
		"validate_sqli",
		"Deterministic Gate 1 SQL-injection validator: DB error or boolean differential (technical signal) AND a UNION-reflected marker (impact). You do not decide the verdict — the validator does.",
		validateSqli,
	);
	registerValidator(
		"validate_command_injection",
		"Deterministic Gate 1 command-injection validator: an injected echo-marker appears in the response (technical signal) AND id/uname output confirms real host execution (impact).",
		validateCommandInjection,
	);
	registerValidator(
		"validate_path_traversal",
		"Deterministic Gate 1 path-traversal validator: a traversal payload serves a known system file (e.g. /etc/passwd) from outside the web root — signal and impact in one artifact.",
		validatePathTraversal,
	);
	registerValidator(
		"validate_xss",
		"Deterministic Gate 1 reflected-XSS validator: renders the page in a headless browser and confirms the injected script EXECUTED (set document.title to a nonce) — execution, not mere reflection.",
		validateXss,
	);
}
