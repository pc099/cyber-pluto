/**
 * cockpit: the operator console. A Camp-1 harness lives on this — fast, direct
 * commands to SEE and DRIVE the engagement without spending an LLM turn, plus a
 * live status widget so the engagement state is always in view (the CAI /
 * Claude-Code feel). It reads/writes the Layer 2 state DB directly.
 *
 * Commands (type `/pluto` for a menu that runs them):
 *   /status    engagement overview            /creds     recovered credentials
 *   /findings  findings + drill-down/actions  /scope     in-scope hosts
 *   /nodes     the investigation tree         /kill      engage the kill switch
 *   /attempts  recent tool audit              /approve   Gate 2: human-approve a finding
 *   /report    write a finding report         /unpause   clear an environmental pause
 *   /pluto     the menu
 *
 * Gate 2 is enforced by construction: /approve is an OPERATOR command (the LLM
 * cannot call it), it records a submissions row naming the human approver, and
 * Pluto NEVER submits to a platform itself — the operator files it manually.
 */
import { existsSync, readFileSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
	SessionStartEvent,
	ToolExecutionEndEvent,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { stateDir } from "../state/db.js";
import { type Engagement, getEngagement, startEngagement } from "../state/engagement.js";
import { isJunkEvidence, junkEvidenceReason } from "../shared/evidence-integrity.js";
import { IllegalStatusTransition } from "../state/findings-repo.js";
import type { FindingRow, NodeRow } from "../state/types.js";
import { buildFindingReport } from "./report.js";
import { killSwitchPath } from "../red-lines/kill-switch.js";
import { requestOperatorStop } from "../state/signer-health.js";

const REPORTS_DIR = "reports";
// The pause flag is per-engagement (lifecycle writes it to the state dir); the
// kill switch stays global at repo-root state/.
function pausePath(cwd: string): string {
	return join(stateDir(cwd), "PAUSED");
}
const STATUS_ICON: Record<string, string> = { candidate: "?", validated: "✓", submitted: "→", rejected: "✗" };

function eng(): Engagement | undefined {
	return getEngagement();
}

/** Read the lifecycle's live readout (tokens/cost) — written to the engagement
 * state dir because extensions run in isolated realms and can't share memory. */
function readCost(cwd: string): { contextTokensSeen: number } | undefined {
	try {
		const raw = readFileSync(join(stateDir(cwd), "lifecycle-status.json"), "utf8");
		const o = JSON.parse(raw) as { contextTokensSeen?: number };
		return typeof o.contextTokensSeen === "number" ? { contextTokensSeen: o.contextTokensSeen } : undefined;
	} catch {
		return undefined;
	}
}

function fmtTokens(n: number): string {
	return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : String(n);
}

function fmtFinding(f: FindingRow): string {
	const asset = [f.service, f.product, f.version].filter(Boolean).join(" ") || "unknown";
	return `${STATUS_ICON[f.status] ?? "?"} #${f.id} [${f.status}] ${asset}${f.port ? ` ${f.protocol ?? "tcp"}/${f.port}` : ""}`;
}

function firstIdArg(args: string): number | undefined {
	const m = /\d+/.exec(args);
	return m ? Number(m[0]) : undefined;
}

function refreshWidget(ctx: ExtensionContext): void {
	if (!ctx.hasUI) return;
	const e = eng();
	if (!e) return;
	const t = e.repos.targets.getById(e.targetId);
	const c = e.repos.findings.countByStatus(e.targetId);
	const cap = Number(process.env["PLUTO_MAX_TOOL_CALLS"] ?? 200);
	const cost = readCost(ctx.cwd);
	const untrusted = e.repos.findings.listUntrustedValidated(e.targetId).length;
	ctx.ui.setWidget("pluto-status", [
		`🪐 pluto · ${t?.host ?? t?.label ?? "?"} · phase ${t?.phase ?? "recon"}`,
		`findings ✓${c.validated} ?${c.candidate} →${c.submitted} ✗${c.rejected}${untrusted ? ` ⚠${untrusted}` : ""} · tree ${e.repos.nodes.countByTarget(e.targetId)} · creds ${e.repos.credentials.countByTarget(e.targetId)} · calls ${e.repos.attempts.countByTarget(e.targetId)}/${cap}${cost ? ` · ~${fmtTokens(cost.contextTokensSeen)} tok` : ""}`,
	]);
}

// --- actions (shared by direct commands and the /pluto menu) ----------------

async function showStatus(ctx: ExtensionCommandContext): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	const t = e.repos.targets.getById(e.targetId);
	const c = e.repos.findings.countByStatus(e.targetId);
	const untrusted = e.repos.findings.listUntrustedValidated(e.targetId).length;
	await ctx.ui.select("Engagement status", [
		`target    ${t?.host ?? t?.label}  (phase ${t?.phase ?? "recon"})`,
		`scope     ${t?.scope_notes ?? process.env["PLUTO_SCOPE_HOSTS"] ?? t?.host ?? "?"}`,
		`findings  validated ${c.validated} · candidate ${c.candidate} · submitted ${c.submitted} · rejected ${c.rejected}`,
		...(untrusted > 0 ? [`⚠ UNVERIFIED  ${untrusted} finding(s) read 'validated' but FAIL Gate-1 signature (possible tampering)`] : []),
		`tree      ${e.repos.nodes.countByTarget(e.targetId)} nodes`,
		`creds     ${e.repos.credentials.countByTarget(e.targetId)}`,
		`calls     ${e.repos.attempts.countByTarget(e.targetId)} / ${process.env["PLUTO_MAX_TOOL_CALLS"] ?? 200}`,
		`tokens    ~${fmtTokens(readCost(ctx.cwd)?.contextTokensSeen ?? 0)} est. / ${fmtTokens(Number(process.env["PLUTO_MAX_TOKENS"] ?? 4_000_000))} cap`,
	]);
	refreshWidget(ctx);
}

async function showSummary(ctx: ExtensionCommandContext): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	const t = e.repos.targets.getById(e.targetId);
	const c = e.repos.findings.countByStatus(e.targetId);
	const untrusted = e.repos.findings.listUntrustedValidated(e.targetId).length;
	const creds = e.repos.credentials.listByTarget(e.targetId);
	const verified = e.repos.findings.listByTarget(e.targetId).filter((f) => e.repos.findings.isValidatedTrustworthy(f.id)).length;
	const lines = [
		`target     ${t?.host ?? t?.label} (${t?.phase ?? "recon"})`,
		`findings   ✓${c.validated} validated · ?${c.candidate} candidate · →${c.submitted} submitted · ✗${c.rejected} rejected`,
		...(untrusted > 0 ? [`⚠ ${untrusted} 'validated' finding(s) FAIL Gate-1 signature (untrusted — possible tampering)`] : []),
		`creds      ${creds.length} recovered${creds.length ? `: ${creds.map((r) => r.username ?? "?").join(", ")}` : ""}`,
		`tree       ${e.repos.nodes.countByTarget(e.targetId)} nodes · ${e.repos.attempts.countByTarget(e.targetId)} attempts`,
		"────────────────────────────────────────────",
		`Verified current findings: ${verified}. Credential records and candidates do not establish an execution foothold.`,
	];
	await ctx.ui.select("Engagement summary", lines);
}

async function doReport(ctx: ExtensionCommandContext, e: Engagement, findingId: number): Promise<void> {
	const finding = e.repos.findings.getById(findingId);
	if (!finding) return void ctx.ui.notify(`No finding #${findingId}.`, "warning");
	const target = e.repos.targets.getById(finding.target_id);
	if (!target) return void ctx.ui.notify("No target for finding.", "error");
	// Item-0 enforcement at the report consumer: a finding can read 'validated'
	// in the pluto-writable DB without a valid Gate-1 promotion signature (a
	// forge). Carry the verdict into the report so a forged one is never dressed
	// up as a genuine submission-ready finding.
	const trustworthy = e.repos.findings.isValidatedTrustworthy(findingId);
	const md = buildFindingReport({
		finding,
		target,
		validations: e.repos.validations.listByFinding(findingId),
		credentials: e.repos.credentials.listByTarget(finding.target_id),
		trustworthy,
	});
	const rel = join(REPORTS_DIR, `finding-${findingId}.md`);
	await mkdir(join(ctx.cwd, REPORTS_DIR), { recursive: true });
	await writeFile(join(ctx.cwd, rel), md, "utf8");
	if (!trustworthy) {
		ctx.ui.notify(
			`⚠ Report written (${rel}) but finding #${findingId}'s Gate-1 promotion signature is MISSING/INVALID — treat as UNVERIFIED (possible tampering); do NOT submit without re-validating.`,
			"warning",
		);
	} else {
		ctx.ui.notify(`Report written: ${rel}`, "info");
	}
}

async function doApprove(ctx: ExtensionCommandContext, e: Engagement, findingId: number): Promise<void> {
	const finding = e.repos.findings.getById(findingId);
	if (!finding) return void ctx.ui.notify(`No finding #${findingId}.`, "warning");
	if (finding.status !== "validated") {
		return void ctx.ui.notify(`Finding #${findingId} is '${finding.status}'. Only a VALIDATED finding can be approved (Gate 2).`, "warning");
	}
	// Gate-1 enforcement BEFORE any submissions row is written: refuse to approve
	// a 'validated' finding whose promotion signature is missing/invalid. Checked
	// here (not only in markSubmitted) so a forged finding never even produces a
	// spurious approver record.
	if (!e.repos.findings.isValidatedTrustworthy(findingId)) {
		return void ctx.ui.notify(
			`Finding #${findingId} reads 'validated' but its Gate-1 promotion signature is MISSING or INVALID — refusing approval (possible tampering). Re-validate it before it can be submitted.`,
			"error",
		);
	}
	const ok = await ctx.ui.confirm(
		"Gate 2 — human approval",
		`Approve finding #${findingId} (${fmtFinding(finding)}) for external submission?\nThis records YOU as the approver. Pluto will NOT submit it — you file it on the platform yourself.`,
	);
	if (!ok) return void ctx.ui.notify("Approval cancelled.", "info");
	const approver = (await ctx.ui.input("Approver name (compliance record)", process.env["USER"] ?? "operator")) || process.env["USER"] || "operator";
	const program = (await ctx.ui.input("Program / handle (optional)", process.env["PLUTO_PROGRAM"] ?? "")) || null;
	try {
		// All operator UI awaits finish before the transaction. Recheck current
		// status/attestation under the write lock so changed evidence cannot leave
		// a stale approval row behind.
		e.db.exec("BEGIN IMMEDIATE");
		let sub;
		try {
			const current = e.repos.findings.getById(findingId);
			if (current?.status !== "validated" || !e.repos.findings.isValidatedTrustworthy(findingId)) {
				throw new IllegalStatusTransition(`Finding #${findingId} changed while awaiting approval or has no verified current attestation; approval refused.`);
			}
			sub = e.repos.submissions.create({ findingId, approvedBy: approver, program });
			e.repos.findings.markSubmitted(findingId);
			e.db.exec("COMMIT");
		} catch (err) {
			e.db.exec("ROLLBACK");
			throw err;
		}
		ctx.ui.notify(`Approved. submissions #${sub.id} by ${approver}. Finding #${findingId} → submitted. File it on the platform manually.`, "info");
		refreshWidget(ctx);
	} catch (err) {
		ctx.ui.notify(err instanceof IllegalStatusTransition ? err.message : `Approval failed: ${String(err)}`, "error");
	}
}

async function showFindingDetail(ctx: ExtensionCommandContext, e: Engagement, finding: FindingRow): Promise<void> {
	const vs = e.repos.validations.listByFinding(finding.id);
	const trustworthy = e.repos.findings.isValidatedTrustworthy(finding.id);
	const detail = [
		fmtFinding(finding),
		...((finding.status === "validated" || finding.status === "submitted") && !trustworthy
			? ["  ⚠ UNVERIFIED — Gate-1 promotion signature missing/invalid (possible tampering)"]
			: []),
		...vs.map((v) => `  gate1 ${v.validator} passed=${v.passed} — ${(v.diff_summary ?? "").slice(0, 90)}`),
		...vs.filter((v) => v.baseline_ref).map((v) => `  evidence ${v.baseline_ref}`),
	];
	const ACT_REPORT = "▶ Generate report";
	const ACT_APPROVE = "▶ Approve for submission (Gate 2)";
	const options = [...detail, "──────────"];
	// A validated finding can always be reported (the report itself flags an
	// unverified one), but only a trustworthy one may be approved for submission.
	if (finding.status === "validated") {
		options.push(ACT_REPORT);
		if (trustworthy) options.push(ACT_APPROVE);
	} else if (finding.status === "submitted") options.push(ACT_REPORT);
	const choice = await ctx.ui.select(`Finding #${finding.id}`, options);
	if (choice === ACT_REPORT) await doReport(ctx, e, finding.id);
	else if (choice === ACT_APPROVE) await doApprove(ctx, e, finding.id);
}

async function showFindings(ctx: ExtensionCommandContext, filterArg: string): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	let list = e.repos.findings.listByTarget(e.targetId);
	const filter = filterArg.trim().toLowerCase();
	if (filter) list = list.filter((f) => f.status === filter);
	if (list.length === 0) return void ctx.ui.notify(filter ? `No '${filter}' findings.` : "No findings yet.", "info");
	const choice = await ctx.ui.select(`Findings${filter ? ` [${filter}]` : ""} — select to drill in`, list.map(fmtFinding));
	if (!choice) return;
	const id = firstIdArg(choice);
	const f = id ? e.repos.findings.getById(id) : undefined;
	if (f) await showFindingDetail(ctx, e, f);
}

async function showNodes(ctx: ExtensionCommandContext): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	const nodes = e.repos.nodes.listByTarget(e.targetId);
	const byParent = new Map<number | null, NodeRow[]>();
	for (const n of nodes) {
		if (!byParent.has(n.parent_id)) byParent.set(n.parent_id, []);
		byParent.get(n.parent_id)?.push(n);
	}
	const out: string[] = [];
	const walk = (parent: number | null, depth: number) => {
		for (const n of byParent.get(parent) ?? []) {
			out.push(`${"  ".repeat(depth)}#${n.id} [${n.node_type}] p${n.priority} (${n.status}) ${n.label}`);
			walk(n.id, depth + 1);
		}
	};
	walk(null, 0);
	await ctx.ui.select(`Investigation tree (${nodes.length} nodes)`, out.length ? out : ["(empty)"]);
}

async function showAttempts(ctx: ExtensionCommandContext): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	const rows = e.repos.attempts.recentByTarget(e.targetId, 40);
	const lines = rows.map(
		(a) => `#${a.id} ${a.tool}${a.tactic ? ` [${a.technique ?? a.tactic}]` : ""} — ${a.command.slice(0, 80)}${a.outcome ? `  (${a.outcome})` : ""}`,
	);
	await ctx.ui.select(`Recent attempts (${rows.length})`, lines.length ? lines : ["(none)"]);
}

async function showCreds(ctx: ExtensionCommandContext): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	const rows = e.repos.credentials.listByTarget(e.targetId);
	if (rows.length === 0) return void ctx.ui.notify("No credentials recorded yet.", "info");
	await ctx.ui.select(
		`Recovered credentials (${rows.length})`,
		rows.map((c) => `#${c.id} ${c.username ?? "?"}${c.secret ? ` : ${c.secret}` : ""}${c.secret_type ? ` (${c.secret_type})` : ""}${c.source ? ` — ${c.source}` : ""}`),
	);
}

async function showScope(ctx: ExtensionCommandContext): Promise<void> {
	const e = eng();
	const t = e?.repos.targets.getById(e.targetId);
	ctx.ui.notify(`In scope: ${process.env["PLUTO_SCOPE_HOSTS"] ?? t?.host ?? "?"}${t?.scope_notes ? `\nROE: ${t.scope_notes}` : ""}`, "info");
}

async function doResume(ctx: ExtensionCommandContext): Promise<void> {
	const p = pausePath(ctx.cwd);
	if (!existsSync(p)) return void ctx.ui.notify("Engagement is not paused.", "info");
	await rm(p, { force: true });
	ctx.ui.notify("Resumed — the environmental pause has been cleared.", "info");
}

async function doKill(ctx: ExtensionCommandContext): Promise<void> {
	const ok = await ctx.ui.confirm("Kill switch", "Halt the engagement now? The next tool call is blocked and the harness stops.");
	if (!ok) return void ctx.ui.notify("Kill switch not engaged.", "info");
	if (process.env.PLUTO_SANDBOX_MODE === "requested") {
		const socket = process.env.PLUTO_PROMOTION_SIGNER_SOCK;
		if (!socket) throw new Error("Sandbox operator stop has no configured signing/control endpoint");
		await requestOperatorStop(socket);
	} else {
		const path = killSwitchPath(ctx.cwd);
		await mkdir(dirname(path), { recursive: true });
		await writeFile(path, `engaged by operator ${new Date().toISOString()}\n`, "utf8");
	}
	ctx.ui.notify("KILL SWITCH ENGAGED — the harness halts at the next tool call.", "warning");
}

async function approveMenu(ctx: ExtensionCommandContext, args: string): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	let id = firstIdArg(args);
	if (id === undefined) {
		// Only trustworthy validated findings are approvable; an unverified one
		// cannot be submitted, so don't offer it (doApprove refuses it anyway).
		const validated = e.repos.findings
			.listByTarget(e.targetId)
			.filter((f) => f.status === "validated" && e.repos.findings.isValidatedTrustworthy(f.id));
		const untrusted = e.repos.findings.listUntrustedValidated(e.targetId).length;
		if (validated.length === 0) {
			return void ctx.ui.notify(
				untrusted > 0
					? `No approvable findings. ${untrusted} finding(s) read 'validated' but FAIL Gate-1 signature verification (possible tampering) — re-validate them.`
					: "No validated findings awaiting approval.",
				untrusted > 0 ? "warning" : "info",
			);
		}
		const choice = await ctx.ui.select("Approve which validated finding?", validated.map(fmtFinding));
		id = choice ? firstIdArg(choice) : undefined;
	}
	if (id !== undefined) await doApprove(ctx, e, id);
}

async function reportMenu(ctx: ExtensionCommandContext, args: string): Promise<void> {
	const e = eng();
	if (!e) return void ctx.ui.notify("No engagement open.", "warning");
	let id = firstIdArg(args);
	if (id === undefined) {
		const list = e.repos.findings.listByTarget(e.targetId).filter((f) => f.status === "validated" || f.status === "submitted");
		if (list.length === 0) return void ctx.ui.notify("No validated findings to report.", "info");
		const choice = await ctx.ui.select("Report which finding?", list.map(fmtFinding));
		id = choice ? firstIdArg(choice) : undefined;
	}
	if (id !== undefined) await doReport(ctx, e, id);
}

// --- extension --------------------------------------------------------------

export default function cockpitExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_e: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
		refreshWidget(ctx);
	});
	pi.on("tool_execution_end", (_e: ToolExecutionEndEvent, ctx: ExtensionContext) => refreshWidget(ctx));

	pi.registerTool({
		name: "record_credential",
		label: "Record Credential",
		description:
			"Record a credential you recovered (from a leaked file, config, cracked hash, etc.) into engagement state so it appears in /creds and reports. Prove access — do not harvest beyond what a finding needs.",
		parameters: Type.Object({
			username: Type.Optional(Type.String()),
			secret: Type.Optional(Type.String({ description: "password/hash/key/token value" })),
			secret_type: Type.Optional(Type.String({ description: "password | hash | key | token" })),
			source: Type.Optional(Type.String({ description: "where/how obtained, e.g. 'IDOR pcap /data/0'" })),
			scope: Type.Optional(Type.String({ description: "what it grants, e.g. 'SSH nathan'" })),
		}),
		async execute(_id, params, _s, _u, ctx) {
			const e = eng();
			if (!e) return { content: [{ type: "text", text: "No engagement DB open." }], details: {} };
			// Evidence-integrity guard (board fix): refuse a junk secret — the hash of
			// an empty/missing file (e.g. md5("")=d41d8cd…) or a placeholder — so a
			// non-capture can never be recorded as a credential/flag.
			if (params.secret && isJunkEvidence(params.secret)) {
				return {
					content: [{ type: "text", text: `NOT recorded: '${params.secret}' is junk evidence (${junkEvidenceReason(params.secret)}). If you md5'd a file, it was empty/missing — that is not a capture. Recover the real value first.` }],
					details: { rejected: true, reason: junkEvidenceReason(params.secret) },
				};
			}
			const allowed = ["password", "hash", "key", "token"];
			const st = params.secret_type && allowed.includes(params.secret_type) ? (params.secret_type as "password" | "hash" | "key" | "token") : null;
			const row = e.repos.credentials.create({
				targetId: e.targetId,
				nodeId: e.rootNodeId,
				username: params.username ?? null,
				secret: params.secret ?? null,
				secretType: st,
				source: params.source ?? null,
				scope: params.scope ?? null,
			});
			refreshWidget(ctx);
			return { content: [{ type: "text", text: `Recorded credential #${row.id} (${params.username ?? "?"}).` }], details: { credentialId: row.id } };
		},
	});

	// Agent-callable, DB-GROUNDED read of the findings ledger. Without this the
	// reasoning core had no sanctioned way to know what it had actually validated,
	// which is how it once hand-wrote fabricated "engagement complete" free-text
	// reports. The ledger — not the model's own narrative — is the source of truth.
	pi.registerTool({
		name: "list_findings",
		label: "List Findings (ledger)",
		description:
			"Read the engagement's findings ledger from state (status is the fact: candidate=speculation, validated=deterministically reproduced). Use THIS, not your own memory, to know what is actually confirmed. A validated finding flagged UNVERIFIED failed Gate-1 signature verification and must not be treated as fact.",
		parameters: Type.Object({
			status: Type.Optional(Type.String({ description: "filter: candidate | validated | submitted | rejected" })),
		}),
		async execute(_id, params, _s, _u, _ctx) {
			const e = eng();
			if (!e) return { content: [{ type: "text", text: "No engagement DB open." }], details: {} };
			const c = e.repos.findings.countByStatus(e.targetId);
			let list = e.repos.findings.listByTarget(e.targetId);
			const filter = params.status?.trim().toLowerCase();
			if (filter) list = list.filter((f) => f.status === filter);
			const lines = list.map((f) => {
				const unverified = (f.status === "validated" || f.status === "submitted") && !e.repos.findings.isValidatedTrustworthy(f.id);
				return `${fmtFinding(f)}${unverified ? "  ⚠ UNVERIFIED (Gate-1 signature missing/invalid — NOT a fact)" : ""}`;
			});
			const summary = `Ledger: validated ${c.validated} · candidate ${c.candidate} · submitted ${c.submitted} · rejected ${c.rejected}`;
			return {
				content: [{ type: "text", text: `${summary}\n${lines.length ? lines.join("\n") : "(no findings match)"}` }],
				details: { counts: c },
			};
		},
	});

	// Agent-callable report generation, constrained to VALIDATED DB FACTS. This is
	// the ONLY sanctioned way to produce a report: it refuses anything that is not
	// genuinely validated (and, under enforcement, signature-verified), so there
	// is no path to a "complete" report for work that was never confirmed. A
	// free-text file the model writes by hand is NOT an authoritative report.
	pi.registerTool({
		name: "generate_report",
		label: "Generate Finding Report (Gate-1 grounded)",
		description:
			"Write a Markdown report from an eligible finding's recorded Gate-1 evidence and verified current attestation. Refuses missing verification or an ineligible current status. Evidence genuineness requires review; Gate 2 remains operator-only.",
		parameters: Type.Object({ finding_id: Type.Number({ description: "id of a VALIDATED finding" }) }),
		async execute(_id, params, _s, _u, ctx) {
			const e = eng();
			if (!e) return { content: [{ type: "text", text: "No engagement DB open." }], details: {} };
			const finding = e.repos.findings.getById(params.finding_id);
			if (!finding) return { content: [{ type: "text", text: `No finding #${params.finding_id}.` }], details: {} };
			if (finding.status !== "validated" && finding.status !== "submitted") {
				return {
					content: [
						{
							type: "text",
							text: `Refused: finding #${params.finding_id} is '${finding.status}', not 'validated'. Only a deterministically validated finding can be reported — validate it first with the validate_* tools. No report was written.`,
						},
					],
					details: { refused: true, status: finding.status },
				};
			}
			if (!e.repos.findings.isValidatedTrustworthy(params.finding_id)) {
				return {
					content: [
						{
							type: "text",
							text: `Refused: finding #${params.finding_id} reads 'validated' but its Gate-1 promotion signature is missing/invalid (possible tampering). No report was written; re-validate it.`,
						},
					],
					details: { refused: true, untrusted: true },
				};
			}
			const target = e.repos.targets.getById(finding.target_id);
			if (!target) return { content: [{ type: "text", text: "No target for finding." }], details: {} };
			const md = buildFindingReport({
				finding,
				target,
				validations: e.repos.validations.listByFinding(params.finding_id),
				credentials: e.repos.credentials.listByTarget(finding.target_id),
				trustworthy: true,
			});
			const rel = join(REPORTS_DIR, `finding-${params.finding_id}.md`);
			await mkdir(join(ctx.cwd, REPORTS_DIR), { recursive: true });
			await writeFile(join(ctx.cwd, rel), md, "utf8");
			return {
				content: [{ type: "text", text: `Report written to ${rel} from the Gate-1 record for finding #${params.finding_id}. Gate 2 (human approval) is still required before any submission.` }],
				details: { path: rel, findingId: params.finding_id },
			};
		},
	});

	pi.registerCommand("status", { description: "Pluto: engagement overview", handler: (_a, ctx) => showStatus(ctx) });
	pi.registerCommand("summary", { description: "Pluto: honest engagement summary (foothold/creds even at 0 validated)", handler: (_a, ctx) => showSummary(ctx) });
	pi.registerCommand("findings", { description: "Pluto: findings + drill-down actions", handler: (a, ctx) => showFindings(ctx, a) });
	pi.registerCommand("nodes", { description: "Pluto: the investigation tree", handler: (_a, ctx) => showNodes(ctx) });
	pi.registerCommand("attempts", { description: "Pluto: recent tool audit", handler: (_a, ctx) => showAttempts(ctx) });
	pi.registerCommand("creds", { description: "Pluto: recovered credentials", handler: (_a, ctx) => showCreds(ctx) });
	pi.registerCommand("scope", { description: "Pluto: in-scope hosts", handler: (_a, ctx) => showScope(ctx) });
	pi.registerCommand("kill", { description: "Pluto: engage the kill switch", handler: (_a, ctx) => doKill(ctx) });
	// NOTE: named 'unpause', NOT 'resume' — Pi has a built-in /resume that would
	// shadow ours (skipping it in autocomplete), which once left an operator
	// unable to clear an environmental pause. Keep this name distinct.
	pi.registerCommand("unpause", { description: "Pluto: clear an environmental pause and continue", handler: (_a, ctx) => doResume(ctx) });
	pi.registerCommand("approve", { description: "Pluto: Gate 2 — human-approve a finding", handler: (a, ctx) => approveMenu(ctx, a) });
	pi.registerCommand("report", { description: "Pluto: write a finding report", handler: (a, ctx) => reportMenu(ctx, a) });

	const MENU: Array<{ label: string; run: (ctx: ExtensionCommandContext) => Promise<void> }> = [
		{ label: "/status   — engagement overview", run: showStatus },
		{ label: "/summary  — honest run summary (foothold/creds even at 0 validated)", run: showSummary },
		{ label: "/findings — findings + drill-down actions", run: (ctx) => showFindings(ctx, "") },
		{ label: "/nodes    — investigation tree", run: showNodes },
		{ label: "/attempts — recent tool audit", run: showAttempts },
		{ label: "/creds    — recovered credentials", run: showCreds },
		{ label: "/scope    — in-scope hosts", run: showScope },
		{ label: "/approve  — Gate 2: human-approve a finding", run: (ctx) => approveMenu(ctx, "") },
		{ label: "/report   — write a finding report", run: (ctx) => reportMenu(ctx, "") },
		{ label: "/unpause  — clear an environmental pause", run: doResume },
		{ label: "/kill     — engage the kill switch", run: doKill },
	];
	pi.registerCommand("pluto", {
		description: "Pluto: operator console menu",
		handler: async (_a, ctx) => {
			const choice = await ctx.ui.select("Pluto console — pick an action", MENU.map((m) => m.label));
			const item = choice ? MENU.find((m) => m.label === choice) : undefined;
			if (item) await item.run(ctx);
		},
	});
}
