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
import { existsSync, readFileSync } from "node:fs";
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
import { checkHardCaps, detectStuck, detectUnhealthy } from "./checks.js";

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
		stuckRepeatThreshold: num("PLUTO_STUCK_REPEAT", 3),
		stuckWindow: num("PLUTO_STUCK_WINDOW", 8),
		stuckEscalateAfter: num("PLUTO_STUCK_ESCALATE", 2),
		// Require several CONSECUTIVE unhealthy target responses before pausing,
		// so a single expected blip (one 'connection refused' while testing, a
		// skill file that mentions 'captcha') never pauses the whole engagement.
		unhealthyThreshold: num("PLUTO_UNHEALTHY_THRESHOLD", 3),
	};
}

const PAUSE_FILE = "state/PAUSED";

// In-process lifecycle state for the current run.
const state = {
	unhealthyHits: 0,
	stuckHits: 0,
	nodeCountHistory: [] as number[],
};

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
	});

	pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | undefined> => {
		const engagement = getEngagement();
		if (!engagement) return undefined;
		const cfg = config();
		const target = engagement.repos.targets.getById(engagement.targetId);

		// 1. Hard caps — deterministic force-stop.
		const toolCallCount = engagement.repos.attempts.countByTarget(engagement.targetId);
		const elapsed = target ? elapsedSeconds(target.created_at) : 0;
		const caps = checkHardCaps(toolCallCount, elapsed, {
			maxToolCalls: cfg.maxToolCalls,
			maxWallClockSeconds: cfg.maxWallClockSeconds,
		});
		if (caps.stop) {
			await logEvent(ctx.cwd, { kind: "hard_cap_stop", cap: caps.kind, reason: caps.reason, toolCallCount, elapsed });
			console.error(`[pluto/lifecycle] ENGAGEMENT STOPPED — ${caps.reason}`);
			ctx.shutdown();
			return { block: true, terminate: true, reason: `Engagement force-stopped: ${caps.reason}. This is a deterministic hard cap (§10.5), not overridable by the agent.` };
		}

		// 2. Environmental pause — target is the problem; flag for review.
		// File-based (like the kill switch) so it survives across extension
		// realms and the operator can clear it with /resume.
		if (existsSync(join(ctx.cwd, PAUSE_FILE))) {
			let reason = "target-health signal";
			try {
				reason = readFileSync(join(ctx.cwd, PAUSE_FILE), "utf8").trim() || reason;
			} catch {
				// keep default
			}
			return {
				block: true,
				reason: `Engagement PAUSED — ${reason} (§10.5). Flagged for review; not burning budget against an untestable target. The operator can resume with /resume.`,
			};
		}

		// 3. Stuck detection — nudge to KB/skill first, escalate only if it persists.
		const recentCommands = engagement.repos.attempts.recentCommandsByTarget(engagement.targetId, cfg.stuckWindow);
		const nodeCountNow = engagement.repos.nodes.countByTarget(engagement.targetId);
		state.nodeCountHistory.push(nodeCountNow);
		const windowStartIdx = Math.max(0, state.nodeCountHistory.length - cfg.stuckWindow - 1);
		const nodeCountAtWindowStart = state.nodeCountHistory[windowStartIdx] ?? nodeCountNow;
		const stuck = detectStuck({
			command: commandText(event),
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
		if (existsSync(join(ctx.cwd, PAUSE_FILE))) return;

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
				await writeFile(join(ctx.cwd, PAUSE_FILE), reason, "utf8");
			} catch (err) {
				console.error("[pluto/lifecycle] failed to write pause file:", err);
			}
			state.unhealthyHits = 0;
			await logEvent(ctx.cwd, { kind: "environmental_pause", signal, reason });
			console.error(`[pluto/lifecycle] ENGAGEMENT PAUSED — ${reason}. Operator: /resume to continue.`);
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
