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
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AgentToolResult, ExtensionAPI, ExtensionContext, SessionStartEvent } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { stateDir } from "../state/db.js";
import { type Engagement, getEngagement, startEngagement } from "../state/engagement.js";
import { type FindingRow } from "../state/types.js";
import { validateCommandInjection } from "./command-injection.js";
import { validateFileWriteRce } from "./file-write-rce.js";
import { type GateReport, recordAndGate } from "./gate.js";
import { validateIdor } from "./idor.js";
import { validatePathTraversal } from "./path-traversal.js";
import { validatePrivilegeEscalation } from "./privilege-escalation.js";
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

	// IDOR takes two object URLs (yours vs another's) + your identity header,
	// not the query-injection param shape, so it registers on its own.
	pi.registerTool({
		name: "validate_idor",
		label: "Validate IDOR (Gate 1)",
		description:
			"Deterministic Gate 1 IDOR / broken-access-control validator: fetches YOUR object and ANOTHER owner's object with your identity, and confirms differential access (the other returns 200 with different, substantial data) while an unauthenticated request is denied (proving it's access-controlled, not public). You do not decide the verdict — the validator does.",
		parameters: Type.Object({
			finding_id: Type.Number({ description: "Candidate finding id from record_candidate" }),
			own_url: Type.String({ description: "URL of a resource that belongs to your identity" }),
			other_url: Type.String({ description: "URL of a resource that belongs to another identity (the IDOR target)" }),
			cookie: Type.Optional(Type.String({ description: "Session cookie value for your identity, e.g. 'session=abc123'" })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const loaded = loadFinding(params.finding_id);
			if (isResult(loaded)) return loaded;
			const headers = params.cookie ? { Cookie: params.cookie } : undefined;
			const report = await validateIdor({ ownUrl: params.own_url, otherUrl: params.other_url, headers });
			return recordAndGate(ctx.cwd, loaded.engagement, params.finding_id, report);
		},
	});

	pi.registerTool({
		name: "validate_file_write_rce",
		label: "Validate File-Write → RCE (Gate 1)",
		description:
			"Deterministic Gate 1 validator for arbitrary-file-write / file-upload → RCE. You give the write primitive DECLARATIVELY (the write URL, the field carrying the filename, the field carrying the content, and where written files surface). The validator captures a clean baseline FIRST, writes a canary and confirms it is served, then proves code execution with an INERT self-deleting arithmetic file (7*7→49) — it does NOT plant a command shell. It cleans up its artifacts and you do not decide the verdict. Exec proven → file_write_rce; write-only → the lesser arbitrary_file_write.",
		parameters: Type.Object({
			finding_id: Type.Number({ description: "Candidate finding id from record_candidate" }),
			write_url: Type.String({ description: "URL that performs the file write (the vulnerable endpoint)" }),
			file_field: Type.String({ description: "Form field carrying the target filename, e.g. 'filename'" }),
			content_field: Type.String({ description: "Form field carrying the file content, e.g. 'content'" }),
			fetch_url_template: Type.String({ description: "Where written files surface; use {name} for the filename, e.g. 'http://10.0.0.5:81/{name}'" }),
			content_type: Type.Optional(Type.String({ description: "'form' (default) or 'multipart'" })),
			cookie: Type.Optional(Type.String({ description: "Session cookie if the write/fetch needs auth" })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const loaded = loadFinding(params.finding_id);
			if (isResult(loaded)) return loaded;
			const report = await validateFileWriteRce({
				writeUrl: params.write_url,
				fileField: params.file_field,
				contentField: params.content_field,
				fetchUrlTemplate: params.fetch_url_template,
				contentType: params.content_type === "multipart" ? "multipart" : "form",
				cookie: params.cookie,
			});
			// †C5: a cleanup we could not confirm is a do-no-harm problem, NOT a
			// verdict problem — raise a BLOCKING pause (same file-based mechanism the
			// lifecycle honors) so the operator removes the artifact, then /unpause.
			if (report.cleanupFailed) {
				try {
					writeFileSync(
						join(stateDir(ctx.cwd), "PAUSED"),
						`file_write_rce left an artifact that could not be auto-removed: ${report.artifactRefs?.join(", ")}. Remove the backing file(s), then /unpause.`,
					);
				} catch {
					/* the alert is also in the tool result + evidence below */
				}
			}
			return recordAndGate(ctx.cwd, loaded.engagement, params.finding_id, report);
		},
	});

	// Privilege escalation makes ROOT a Gate-1 fact (before this it was only log
	// evidence). It takes two execution-channel TEMPLATES — unprivileged and
	// escalated — not the web-injection param shape, so it registers on its own.
	pi.registerTool({
		name: "validate_privilege_escalation",
		label: "Validate Privilege Escalation → root (Gate 1)",
		description:
			"Deterministic Gate 1 validator that root was actually achieved — so an escalation becomes a `validated` ledger fact, not just a transcript claim. You provide two shell-command TEMPLATES, each containing the literal {probe} placeholder: baseline_exec runs a probe as the CURRENT unprivileged user, escalated_exec runs it THROUGH your escalation vector (sudo / a planted SUID bash / a kernel-exploit shell / a cron payload). The validator confirms the baseline is non-root, that the escalated channel returns uid=0 for a nonce'd probe (not a canned banner), AND that the escalated channel can read a root-only file (/etc/shadow by default) the baseline cannot — captured as the exit-code differential only, never the file content. You do not decide the verdict; a euid=0 with no working read differential does NOT pass.",
		parameters: Type.Object({
			finding_id: Type.Number({ description: "Candidate finding id from record_candidate" }),
			baseline_exec: Type.String({ description: "Command template running {probe} as the current unprivileged user, e.g. \"sshpass -p www ssh www-data@10.0.0.5 {probe}\"" }),
			escalated_exec: Type.String({ description: "Command template running {probe} through the escalation vector, e.g. \"sshpass -p www ssh www-data@10.0.0.5 sudo {probe}\"" }),
			root_only_path: Type.Optional(Type.String({ description: "Root-only file for the read differential (default /etc/shadow); only its readability is used" })),
			timeout_ms: Type.Optional(Type.Number({ description: "Per-exec timeout in ms (default 15000)" })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const loaded = loadFinding(params.finding_id);
			if (isResult(loaded)) return loaded;
			const report = await validatePrivilegeEscalation({
				baselineExecTemplate: params.baseline_exec,
				escalatedExecTemplate: params.escalated_exec,
				rootOnlyReadPath: params.root_only_path,
				timeoutMs: params.timeout_ms,
			});
			return recordAndGate(ctx.cwd, loaded.engagement, params.finding_id, report);
		},
	});
}
