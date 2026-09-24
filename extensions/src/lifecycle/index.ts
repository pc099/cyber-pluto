/**
 * lifecycle: the §10.5 engagement-lifecycle governor. Three DETERMINISTIC
 * mechanisms, all computed by the harness from the state schema — never left
 * to the reasoning core to decide mid-task (the same principle as the two
 * gates). Realized as a pre-execution `tool_call` hook (caps + pause + stuck)
 * plus a `tool_execution_end` watcher (target health):
 *
 *  1. Hard caps — max tool-call count + max wall-clock per target engagement
 *     (the binding constraints under a subscription, not a dollar budget).
 *     Hitting either force-stops with an explicit status.
 *  2. Environmental pause — target-health signals (unresponsive, CAPTCHA, WAF,
 *     account-locked) auto-pause and flag for review rather than burning the
 *     budget against a target that can't currently be tested.
 *  3. Stuck detection — computed off the state tree (no new nodes, or the same
 *     call repeated). It does NOT force-stop: first it makes Pluto consult an
 *     untried KB/skill angle; only if the stall persists does it escalate to
 *     Chaitanya. A bypass/evasion mutation is a DIFFERENT call, so it reads as
 *     progress, not repetition (§6.5.2).
 */
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
	ToolCallEvent,
	ToolCallEventResult,
	ToolExecutionEndEvent,
} from "@earendil-works/pi-coding-agent";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { stateDir } from "../state/db.js";
import { FOOTHOLD_CLASSES } from "../validators/foothold-orchestration.js";
import { checkHardCaps, checkTryBudget, classifyAttack, DEFAULT_TRY_BUDGET, detectStuck, detectUnhealthy } from "./checks.js";
import { buildRunSummary } from "./run-summary.js";
import { resolveVerifier } from "../state/promotion-verifier.js";
import type { Engagement } from "../state/engagement.js";

const LOG = { dir: "logs", file: "lifecycle.jsonl" };

function num(env: string, dflt: number): number {
	const v = Number(process.env[env]);
	return Number.isFinite(v) && v > 0 ? v : dflt;
}

/** Like num(), but a hard cap can be *disabled*: 0 / "none" / "unlimited" /
 * "off" means no cap (Infinity), which checkHardCaps' `>=` never trips. Used
 * for the two hard caps so an operator on a flat-rate subscription can run
 * uncapped (stuck-detection + the kill switch remain the real safeguards). */
function capNum(env: string, dflt: number): number {
	const raw = (process.env[env] ?? "").trim().toLowerCase();
	if (raw === "0" || raw === "none" || raw === "unlimited" || raw === "off") return Number.POSITIVE_INFINITY;
	const v = Number(raw);
	return Number.isFinite(v) && v > 0 ? v : dflt;
}

function config() {
	return {
		maxToolCalls: capNum("PLUTO_MAX_TOOL_CALLS", 200),
		maxWallClockSeconds: capNum("PLUTO_MAX_WALLCLOCK_S", 3600),
		// Cost is the real constraint on a metered provider. Cap estimated
		// cumulative tokens (default 4M — well above a normal box, well below the
		// 24M runaway). 0/unlimited disables it like the other caps.
		maxTokens: capNum("PLUTO_MAX_TOKENS", 4_000_000),
		stuckRepeatThreshold: num("PLUTO_STUCK_REPEAT", 3),
		stuckWindow: num("PLUTO_STUCK_WINDOW", 8),
		stuckEscalateAfter: num("PLUTO_STUCK_ESCALATE", 2),
		// Require several CONSECUTIVE unhealthy target responses before pausing,
		// so a single expected blip (one 'connection refused' while testing, a
		// skill file that mentions 'captcha') never pauses the whole engagement.
		unhealthyThreshold: num("PLUTO_UNHEALTHY_THRESHOLD", 3),
	};
}

// The environmental-pause flag lives in the PER-ENGAGEMENT state dir (like
// lifecycle-status.json), NOT repo-root, so a stale pause from a previous
// engagement can never block a new one. (The kill switch stays global.)
function pausePath(cwd: string): string {
	return join(stateDir(cwd), "PAUSED");
}

// In-process lifecycle state for THIS run (reset each process).
const state = {
	unhealthyHits: 0,
	stuckHits: 0,
	nodeCountHistory: [] as number[],
	// Active wall-clock is measured from process start, NOT targets.created_at:
	// with per-engagement DBs a target persists across resumes, so created_at
	// would false-stop any engagement older than the wall cap on its first call.
	sessionStart: Date.now(),
	// Estimated context throughput (NOT dollar cost): Σ over TURNS of the
	// context size that turn. Accumulated once per turn (guarded by a change in
	// context size) so N parallel tool calls in one turn aren't counted N times.
	// Cache reads bill far below full price, so this OVER-estimates spend and
	// is a conservative ceiling + a rough readout, never a bill.
	contextTokensSeen: 0,
	lastContextTokens: -1,
};

const HEADLESS = ((): boolean => {
	const v = (process.env["PLUTO_HEADLESS"] ?? "").toLowerCase();
	return v === "1" || v === "true" || v === "yes";
})();

/** Publish a live engagement readout (tokens/cost, tool calls, elapsed) to the
 * engagement's state dir so the operator console (/status) can show it. Written
 * to a file because extensions run in isolated realms and cannot share memory. */
async function publishStatus(cwd: string, status: { contextTokensSeen: number; toolCalls: number; elapsed: number }): Promise<void> {
	try {
		const dir = stateDir(cwd);
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "lifecycle-status.json"), JSON.stringify({ ts: new Date().toISOString(), ...status }), "utf8");
	} catch {
		// a readout write failure must never affect the engagement
	}
}

/** Deterministic run-summary telemetry (Decision 0006): a persisted,
 * comparable record of how the run went (milestone reached, foothold/root,
 * stop reason, counts, per-class attempts). Written to the state dir so the
 * board reviews facts, not transcripts. Best-effort — never affects the run. */
async function publishRunSummary(cwd: string, engagement: Engagement, stopReason: string, elapsed: number, tokens: number): Promise<void> {
	try {
		const tid = engagement.targetId;
		const target = engagement.repos.targets.getById(tid);
		const attemptsByClass: Record<string, number> = {};
		for (const cmd of engagement.repos.attempts.allCommandsByTarget(tid)) {
			const cls = classifyAttack(cmd);
			if (cls) attemptsByClass[cls] = (attemptsByClass[cls] ?? 0) + 1;
		}
		const summary = buildRunSummary({
			targetLabel: target?.label ?? "unknown",
			host: target?.host ?? null,
			stopReason,
			counts: engagement.repos.findings.countByStatus(tid),
			untrustedValidated: engagement.repos.findings.listUntrustedValidated(tid).length,
			signatureEnforced: resolveVerifier() !== undefined,
			credsRecovered: engagement.repos.credentials.listByTarget(tid).length,
			nodeCount: engagement.repos.nodes.countByTarget(tid),
			attemptCount: engagement.repos.attempts.countByTarget(tid),
			attemptsByClass,
			hasFoothold: engagement.repos.findings.hasValidatedFootholdClass(tid, [...FOOTHOLD_CLASSES]),
			hasRoot: engagement.repos.findings.hasValidatedFootholdClass(tid, ["privilege_escalation"]),
			elapsedSeconds: Math.floor(elapsed),
			contextTokensSeen: tokens,
		});
		await mkdir(stateDir(cwd), { recursive: true });
		await writeFile(join(stateDir(cwd), "run-summary.json"), JSON.stringify(summary, null, 2), "utf8");
	} catch {
		// telemetry must never affect the engagement
	}
}

async function logEvent(cwd: string, entry: Record<string, unknown>): Promise<void> {
	try {
		await mkdir(join(cwd, LOG.dir), { recursive: true });
		await appendFile(join(cwd, LOG.dir, LOG.file), `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, "utf8");
	} catch (err) {
		console.error("[pluto/lifecycle] log write failed:", err);
	}
}

function elapsedSeconds(createdAt: string): number {
	// targets.created_at is `datetime('now')` (UTC, space-separated).
	const started = Date.parse(`${createdAt.replace(" ", "T")}Z`);
	return Number.isFinite(started) ? (Date.now() - started) / 1000 : 0;
}

function commandText(event: ToolCallEvent): string {
	if (event.toolName === "bash" && event.input && typeof event.input === "object" && "command" in event.input) {
		return String((event.input as { command: unknown }).command);
	}
	return `${event.toolName}:${JSON.stringify(event.input)}`;
}

export default function lifecycleExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_e: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
		// A brand-new session means the operator is present and starting fresh —
		// never inherit a PAUSED flag from a prior run. (This once deadlocked the
		// harness: a stale pause blocked every tool call with no way to resume.)
		try {
			rmSync(pausePath(ctx.cwd), { force: true });
		} catch {
			/* best effort */
		}
		// Footgun guard (board fix): a bare `pi` (not the `pluto` launcher) sets no
		// PLUTO_TARGET_HOST, so the engagement falls back to the shared default DB
		// whose target is loopback — and the REAL target then reads as out-of-scope,
		// silently wasting a whole session. Warn loudly so the operator relaunches
		// via the launcher instead of grinding against the wrong scope.
		const host = (process.env["PLUTO_TARGET_HOST"] ?? "").trim().toLowerCase();
		if (host === "" || host === "127.0.0.1" || host === "localhost" || host === "::1") {
			console.error(
				"[pluto/lifecycle] ⚠ No real target set (PLUTO_TARGET_HOST is unset/loopback). " +
					"You are probably on the default engagement — the real target will read as OUT OF SCOPE. " +
					"Launch via:  pluto --target <ip> --scope <ip> --label <name>  (not bare `pi`).",
			);
		}
		// Doctrine guard: hand-written "engagement complete" files are NOT
		// authoritative — the state-DB ledger is the only source of completion
		// truth. Warn if any resurfaced at the repo root (they must never be trusted).
		try {
			for (const f of readdirSync(ctx.cwd)) {
				if (/ENGAGEMENT_COMPLETE/i.test(f)) {
					console.error(`[pluto/lifecycle] ⚠ Ignoring hand-written completion file '${f}' — the ledger (/summary, list_findings) is the ONLY source of completion truth.`);
				}
			}
		} catch {
			/* best effort */
		}
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | undefined> => {
		const engagement = getEngagement();
		if (!engagement) return undefined;
		const cfg = config();
		const target = engagement.repos.targets.getById(engagement.targetId);

		// 1. Hard caps — deterministic force-stop. Accumulate the context-token
		// estimate ONCE PER TURN: only add when the context size changed, so the
		// N parallel tool calls of a single turn (one API request) aren't counted
		// N times. Publish a running readout for the operator console.
		try {
			const used = ctx.getContextUsage?.()?.tokens;
			if (typeof used === "number" && used > 0 && used !== state.lastContextTokens) {
				state.contextTokensSeen += used;
				state.lastContextTokens = used;
			}
		} catch {
			// context usage unavailable (e.g. right after compaction) — skip this turn
		}
		const toolCallCount = engagement.repos.attempts.countByTarget(engagement.targetId);
		const elapsed = (Date.now() - state.sessionStart) / 1000; // active run time, not target age
		await publishStatus(ctx.cwd, { contextTokensSeen: state.contextTokensSeen, toolCalls: toolCallCount, elapsed });
		await publishRunSummary(ctx.cwd, engagement, "in_progress", elapsed, state.contextTokensSeen);
		const caps = checkHardCaps(toolCallCount, elapsed, state.contextTokensSeen, {
			maxToolCalls: cfg.maxToolCalls,
			maxWallClockSeconds: cfg.maxWallClockSeconds,
			maxTokens: cfg.maxTokens,
		});
		if (caps.stop) {
			await publishRunSummary(ctx.cwd, engagement, `hard_cap:${caps.kind}`, elapsed, state.contextTokensSeen);
			await logEvent(ctx.cwd, { kind: "hard_cap_stop", cap: caps.kind, reason: caps.reason, toolCallCount, elapsed });
			console.error(`[pluto/lifecycle] ENGAGEMENT STOPPED — ${caps.reason}`);
			ctx.shutdown();
			return { block: true, terminate: true, reason: `Engagement force-stopped: ${caps.reason}. This is a deterministic hard cap (§10.5), not overridable by the agent.` };
		}

		// 2. Environmental pause — target is the problem; flag for review.
		// File-based (like the kill switch) so it survives across extension
		// realms and the operator can clear it with /resume.
		if (existsSync(pausePath(ctx.cwd))) {
			let reason = "target-health signal";
			try {
				reason = readFileSync(pausePath(ctx.cwd), "utf8").trim() || reason;
			} catch {
				// keep default
			}
			// Headless has no operator/console to /resume, so a pause that only
			// BLOCKS would spin on blocked calls until a cap force-stops it,
			// burning budget doing nothing. In headless, a pause is terminal.
			if (HEADLESS) {
				await publishRunSummary(ctx.cwd, engagement, `headless_pause:${reason}`, (Date.now() - state.sessionStart) / 1000, state.contextTokensSeen);
				await logEvent(ctx.cwd, { kind: "environmental_pause_stop", reason });
				console.error(`[pluto/lifecycle] ENGAGEMENT STOPPED (headless) — ${reason}`);
				ctx.shutdown();
				return { block: true, terminate: true, reason: `Engagement stopped — ${reason} (§10.5). No operator is present in headless mode to resume; halting rather than burning budget against an untestable target.` };
			}
			return {
				block: true,
				reason: `Engagement PAUSED — ${reason} (§10.5). Flagged for review; not burning budget against an untestable target. The operator can resume with /unpause. (This is an operator-only console command; you, the agent, cannot clear it — stop and wait rather than retrying tools.)`,
			};
		}

		// 3. Try-budget — a per-class ceiling on high-cost/low-yield attack
		// classes (auth brute, hash crack) so the harness pivots on its own
		// instead of grinding (run-2: one hydra call = ~173k requests; run-3: ~7
		// hydra runs before the operator forced a pivot). Content discovery gets
		// a high ceiling — it is the productive enumeration, not thrash.
		const thisCommand = commandText(event);
		const budgetVerdict = checkTryBudget({
			command: thisCommand,
			priorCommands: engagement.repos.attempts.allCommandsByTarget(engagement.targetId),
			budget: DEFAULT_TRY_BUDGET,
			hasValidatedFoothold: engagement.repos.findings.hasValidatedFootholdClass(engagement.targetId, [...FOOTHOLD_CLASSES]),
		});
		if (budgetVerdict.over) {
			await logEvent(ctx.cwd, { kind: "try_budget_pivot", cls: budgetVerdict.cls, spent: budgetVerdict.spent, reason: budgetVerdict.reason });
			return { block: true, reason: budgetVerdict.guidance };
		}

		// 4. Stuck detection — nudge to KB/skill first, escalate only if it persists.
		const recentCommands = engagement.repos.attempts.recentCommandsByTarget(engagement.targetId, cfg.stuckWindow);
		const nodeCountNow = engagement.repos.nodes.countByTarget(engagement.targetId);
		state.nodeCountHistory.push(nodeCountNow);
		const windowStartIdx = Math.max(0, state.nodeCountHistory.length - cfg.stuckWindow - 1);
		const nodeCountAtWindowStart = state.nodeCountHistory[windowStartIdx] ?? nodeCountNow;
		const stuck = detectStuck({
			command: thisCommand,
			recentCommands,
			repeatThreshold: cfg.stuckRepeatThreshold,
			nodeCountAtWindowStart,
			nodeCountNow,
		});
		if (stuck.stuck) {
			state.stuckHits += 1;
			const escalate = state.stuckHits >= cfg.stuckEscalateAfter;
			await logEvent(ctx.cwd, { kind: escalate ? "stuck_escalate" : "stuck_nudge", signal: stuck.signal, reason: stuck.reason, stuckHits: state.stuckHits });
			const guidance = escalate
				? `Stuck persists after an untried KB/skill lookup — escalating to Chaitanya (§10.5). ${stuck.reason}.`
				: `Stuck detected (${stuck.reason}). Before repeating, consult the knowledge base or a runtime skill for an angle you have NOT yet tried on this line of attack, or try a genuinely different technique (a bypass/evasion counts as progress). This call is blocked to break the loop.`;
			return { block: true, reason: guidance };
		}

		return undefined;
	});

	pi.on("tool_execution_end", async (event: ToolExecutionEndEvent, ctx: ExtensionContext) => {
		// Only judge TARGET health from the vector that actually hits the target
		// (shell tools). File reads, edits, and Pluto's own custom tools must not
		// count — that is what caused false pauses (a skill file mentioning
		// 'captcha', a validator's own probe). Ignore an errored call too: an
		// expected failure (a closed port, a refused test connection) is not the
		// target being unhealthy.
		if (event.toolName !== "bash" && event.toolName !== "powershell") return;
		if (event.isError) return;
		if (existsSync(pausePath(ctx.cwd))) return;

		const signal = detectUnhealthy(extractText(event.result));
		if (!signal) {
			state.unhealthyHits = 0; // a healthy target response resets the streak
			return;
		}
		state.unhealthyHits += 1;
		if (state.unhealthyHits >= config().unhealthyThreshold) {
			const reason = `target-health signal '${signal}' on ${state.unhealthyHits} consecutive responses`;
			try {
				await mkdir(join(ctx.cwd, "state"), { recursive: true });
				await writeFile(pausePath(ctx.cwd), reason, "utf8");
			} catch (err) {
				console.error("[pluto/lifecycle] failed to write pause file:", err);
			}
			state.unhealthyHits = 0;
			await logEvent(ctx.cwd, { kind: "environmental_pause", signal, reason });
			console.error(`[pluto/lifecycle] ENGAGEMENT PAUSED — ${reason}. Operator: /unpause to continue.`);
		}
	});
}

function extractText(result: unknown): string {
	if (!result || typeof result !== "object") return String(result ?? "");
	if ("content" in result && Array.isArray((result as { content: unknown[] }).content)) {
		return (result as { content: Array<{ text?: unknown }> }).content
			.map((c) => (typeof c.text === "string" ? c.text : ""))
			.join("\n");
	}
	return JSON.stringify(result);
}
