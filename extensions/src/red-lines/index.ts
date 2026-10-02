/**
 * red-lines: the §10.4 pre-execution safety gate.
 *
 * This extension is the choke point every tool call is FORCED through: it
 * hooks `tool_call` (which fires before any tool — built-in or custom —
 * executes and can block it) and refuses the call outright if the kill switch
 * is engaged or any red-line rule fires. There is no code path from the
 * reasoning core to a tool that skips this, and because `tool_call` fires for
 * every tool the process exposes, loading this extension covers bash and every
 * custom tool at once.
 *
 * Propagation to delegated sub-agents (§6.4, Session 9): delegation spawns a
 * separate Pi process, which must load THIS extension too. The check itself
 * (check.ts / rules.ts) is a pure, stateless module precisely so a sub-agent
 * re-applies the identical gate with no shared runtime state. The delegation
 * spawner built in Session 9 must include `-e red-lines` for every sub-agent;
 * the contract is documented here so it cannot be forgotten. A delegated agent
 * that could invoke a tool without this hook would be a hole in the gate.
 *
 * Failure direction: this is a safety gate, so anything uncertain blocks. A
 * false block just routes to Chaitanya for approval (§10.4's model); a missed
 * block means a prohibited action ran.
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
	SessionStartEvent,
	ToolCallEvent,
	ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import { buildGrant, commandHash, DEFAULT_GRANT_TTL_MS, type PendingBlock } from "./approvals.js";
import { appendGrant, consumeMatchingGrant, readPendingBlocks, recordPendingBlock, resolveApprovalKey } from "./approvals-store.js";
import { checkRedLines, toInvocation } from "./check.js";
import { isKillSwitchEngaged, killSwitchPath } from "./kill-switch.js";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { logDir } from "../state/db.js";
import { normalizeHost, parseScopeHosts, resolveVhosts } from "./rules.js";

// Session-bound so a grant can NEVER carry into a later session (a stale grant
// weakens the gate — the inverse of the PAUSED file). Regenerated per process;
// the `/allow` console command runs in this same process, so it shares this id.
const SESSION_ID = randomUUID();

const LOG_FILE = "red-lines.jsonl";
const MAX_LOGGED_COMMAND = 2000;

let scopeHosts: Set<string> | undefined;

function resolveScopeHosts(): Set<string> {
	const hosts = new Set<string>();
	const engagement = getEngagement();
	if (engagement) {
		const target = engagement.repos.targets.getById(engagement.targetId);
		if (target?.host) hosts.add(normalizeHost(target.host));
		for (const h of parseScopeHosts(target?.scope_notes)) hosts.add(h);
	}
	for (const h of parseScopeHosts(process.env["PLUTO_SCOPE_HOSTS"])) hosts.add(h);
	// Fold in vhosts that /etc/hosts maps to an already-in-scope IP (recon adds
	// these during an engagement), so a discovered `management.htb → <in-scope IP>`
	// is not blocked. Read fresh each call — this is why scope is resolved per
	// tool-call, not just at session start (a vhost added after start still counts).
	try {
		resolveVhosts(hosts, readFileSync("/etc/hosts", "utf8"));
	} catch {
		// no /etc/hosts (e.g. non-Linux); nothing to fold in
	}
	return hosts;
}

async function logBlock(cwd: string, entry: Record<string, unknown>): Promise<void> {
	const line = `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`;
	try {
		const directory = logDir(cwd);
		await mkdir(directory, { recursive: true });
		await appendFile(join(directory, LOG_FILE), line, "utf8");
	} catch (err) {
		// Never let a logging failure swallow the fact that a block happened.
		console.error("[pluto/red-lines] BLOCK (log write failed):", line, err);
	}
}

export default function redLinesExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
		scopeHosts = resolveScopeHosts();
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | undefined> => {
		// 1. Kill switch — halt-at-any-moment floor of the human role.
		if (isKillSwitchEngaged(ctx.cwd)) {
			const reason = `Kill switch engaged (${killSwitchPath(ctx.cwd)}); halting the harness.`;
			await logBlock(ctx.cwd, {
				kind: "kill_switch",
				toolCallId: event.toolCallId,
				toolName: event.toolName,
			});
			console.error(`[pluto/red-lines] ${reason}`);
			ctx.shutdown();
			return { block: true, reason, terminate: true };
		}

		// 2. Red-lines rules (§10.4). Resolve scope fresh each call so a vhost
		// added to /etc/hosts mid-engagement (pointing at an in-scope IP) is
		// honored; the base cost is a single indexed row + a tiny file read.
		scopeHosts = resolveScopeHosts();
		const inv = toInvocation(event.toolName, event.input);
		const decision = checkRedLines(inv, { scopeHosts });
		if (!decision.allowed) {
			// Operator approval channel: BEFORE re-blocking, consult the grant
			// ledger. A matching, unexpired, single-use, session-bound grant that
			// the operator issued via `/allow` converts this block into an allow —
			// consuming the grant and auditing the override. There is no new allow
			// path for an UN-granted call: it still hits the block below.
			const key = resolveApprovalKey();
			const grant = consumeMatchingGrant(ctx.cwd, {
				sessionId: SESSION_ID,
				toolName: event.toolName,
				commandText: inv.commandText,
				now: Date.now(),
				key,
			});
			if (grant) {
				await logBlock(ctx.cwd, {
					kind: "red_line_override_used",
					toolCallId: event.toolCallId,
					toolName: event.toolName,
					category: decision.category,
					ruleId: decision.ruleId,
					grantId: grant.id,
					approver: grant.approver,
					signed: grant.sig !== undefined,
					command: inv.commandText.slice(0, MAX_LOGGED_COMMAND),
				});
				console.error(`[pluto/red-lines] OVERRIDE — operator grant ${grant.id} (approver: ${grant.approver}) permits this ${decision.category} call once.`);
				return undefined; // allowed by an operator grant
			}

			const cHash = commandHash(event.toolName, inv.commandText);
			const blockId = cHash.slice(0, 8);
			recordPendingBlock(ctx.cwd, {
				ts: new Date().toISOString(),
				blockId,
				sessionId: SESSION_ID,
				toolName: event.toolName,
				category: decision.category,
				ruleId: decision.ruleId,
				reason: decision.reason,
				commandPreview: inv.commandText.slice(0, 200),
				commandHash: cHash,
			});
			await logBlock(ctx.cwd, {
				kind: "red_line",
				toolCallId: event.toolCallId,
				toolName: event.toolName,
				category: decision.category,
				ruleId: decision.ruleId,
				reason: decision.reason,
				blockId,
				command: inv.commandText.slice(0, MAX_LOGGED_COMMAND),
			});
			console.error(
				`[pluto/red-lines] BLOCKED [${decision.category}] ${decision.reason} — operator can grant once via /allow ${blockId}.`,
			);
			return {
				block: true,
				reason:
					`RED-LINE (${decision.category}): ${decision.reason}. Blocked pre-execution. ` +
					`If this is a false positive, the OPERATOR (a human at the console, not you) can grant a one-time exception for this exact command with \`/allow ${blockId}\`. ` +
					`You cannot clear this yourself — do NOT reword the command to evade the gate; stop and wait for the operator.`,
			};
		}

		return undefined; // allowed
	});

	// --- Operator console: /blocks (list) and /allow (grant one-time) --------
	// registerCommand, NOT registerTool: the reasoning core can invoke tools but
	// NOT commands, so the model has no path to grant itself an exception.
	pi.registerCommand("blocks", {
		description: "Pluto: list red-line blocks awaiting an operator /allow",
		handler: (_args: string, ctx: ExtensionCommandContext) => listBlocks(ctx),
	});
	pi.registerCommand("allow", {
		description: "Pluto: grant a ONE-TIME red-line exception for a pending block (operator only). Usage: /allow <blockId>",
		handler: (args: string, ctx: ExtensionCommandContext) => allowBlock(ctx, args),
	});
}

async function listBlocks(ctx: ExtensionCommandContext): Promise<void> {
	const pending = readPendingBlocks(ctx.cwd).filter((b) => b.sessionId === SESSION_ID);
	if (pending.length === 0) return void ctx.ui.notify("No red-line blocks are awaiting approval this session.", "info");
	const seen = new Set<string>();
	const lines: string[] = [];
	for (const b of [...pending].reverse()) {
		if (seen.has(b.blockId)) continue;
		seen.add(b.blockId);
		lines.push(`${b.blockId}  [${b.category}]  ${b.commandPreview}`);
	}
	lines.push("", "Grant one with:  /allow <blockId>   (grants exactly that command, once)");
	await ctx.ui.select("Red-line blocks awaiting /allow", lines);
}

async function allowBlock(ctx: ExtensionCommandContext, args: string): Promise<void> {
	const blockId = args.trim().split(/\s+/)[0] ?? "";
	const pending = readPendingBlocks(ctx.cwd).filter((b) => b.sessionId === SESSION_ID);
	if (!blockId) {
		return void ctx.ui.notify("Usage: /allow <blockId>. Run /blocks to see pending blocks.", "warning");
	}
	const block = [...pending].reverse().find((b) => b.blockId === blockId);
	if (!block) {
		return void ctx.ui.notify(`No pending block '${blockId}' this session. Run /blocks to list them.`, "warning");
	}
	const ok = await ctx.ui.confirm(
		`Red-line exception [${block.category}]`,
		`Grant a ONE-TIME exception and let this exact command run once?\n\n  ${block.commandPreview}\n\nThis waives the red-line for this command only.`,
	);
	if (!ok) return void ctx.ui.notify("Grant cancelled — the block still stands.", "info");
	const approver = (await ctx.ui.input("Approver name (audit record)", process.env["USER"] ?? "operator")) || process.env["USER"] || "operator";
	const key = resolveApprovalKey();
	const grant = buildGrant({ block, approver, ttlMs: DEFAULT_GRANT_TTL_MS, now: Date.now(), key });
	appendGrant(ctx.cwd, grant);
	ctx.ui.notify(
		`Granted (${grant.id.slice(0, 8)}, ${key ? "signed" : "UNSIGNED dev-mode"}): the command may run ONCE within ${Math.round(DEFAULT_GRANT_TTL_MS / 60000)} min. Tell Pluto to retry the exact command.`,
		"info",
	);
}
