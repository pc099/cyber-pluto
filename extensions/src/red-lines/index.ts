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
import { readFileSync } from "node:fs";
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
	ToolCallEvent,
	ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import { checkRedLines, toInvocation } from "./check.js";
import { isKillSwitchEngaged, killSwitchPath } from "./kill-switch.js";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { normalizeHost, parseScopeHosts, resolveVhosts } from "./rules.js";

const LOG_DIR = "logs";
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
		await mkdir(join(cwd, LOG_DIR), { recursive: true });
		await appendFile(join(cwd, LOG_DIR, LOG_FILE), line, "utf8");
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
			await logBlock(ctx.cwd, {
				kind: "red_line",
				toolCallId: event.toolCallId,
				toolName: event.toolName,
				category: decision.category,
				ruleId: decision.ruleId,
				reason: decision.reason,
				command: inv.commandText.slice(0, MAX_LOGGED_COMMAND),
			});
			console.error(
				`[pluto/red-lines] BLOCKED [${decision.category}] ${decision.reason} — requires Chaitanya's explicit approval.`,
			);
			return {
				block: true,
				reason: `RED-LINE (${decision.category}): ${decision.reason}. Blocked pre-execution; this requires explicit human approval before Pluto may proceed.`,
			};
		}

		return undefined; // allowed
	});
}
