/**
 * Deterministic engagement-lifecycle checks (Architecture §10.5). The
 * governing principle: whether to keep going is NOT the reasoning core's call
 * — these are harness checks computed from the state schema, in the same
 * spirit as the two-gate model. Pure functions, so they are trivially testable
 * and identical wherever they run.
 */

export interface HardCaps {
	maxToolCalls: number;
	maxWallClockSeconds: number;
	/** Ceiling on estimated context throughput (Σ context size per turn). This
	 * OVER-estimates dollar spend (cache reads bill far below full price), so it
	 * is a conservative safety ceiling, not a bill — the binding constraint on a
	 * metered provider is cost, and a runaway once hit ~24M tokens of context. */
	maxTokens: number;
}

export type CapVerdict = { stop: true; reason: string; kind: "tool_calls" | "wall_clock" | "tokens" } | { stop: false };

export function checkHardCaps(toolCallCount: number, elapsedSeconds: number, billedTokens: number, caps: HardCaps): CapVerdict {
	if (toolCallCount >= caps.maxToolCalls) {
		return { stop: true, kind: "tool_calls", reason: `tool-call cap reached (${toolCallCount}/${caps.maxToolCalls})` };
	}
	if (elapsedSeconds >= caps.maxWallClockSeconds) {
		return {
			stop: true,
			kind: "wall_clock",
			reason: `wall-clock cap reached (${Math.floor(elapsedSeconds)}s/${caps.maxWallClockSeconds}s)`,
		};
	}
	if (billedTokens >= caps.maxTokens) {
		return {
			stop: true,
			kind: "tokens",
			reason: `context-token ceiling reached (~${(billedTokens / 1e6).toFixed(1)}M/${(caps.maxTokens / 1e6).toFixed(1)}M est. context tokens — a conservative over-estimate, not a bill)`,
		};
	}
	return { stop: false };
}

/** Target-health signals (§10.5): the TARGET, not Pluto, is the problem.
 * Detecting one means auto-pause and flag for review rather than burning the
 * tool-call budget against something that can't currently be tested. */
const UNHEALTHY_SIGNALS: Array<{ signal: string; re: RegExp }> = [
	{ signal: "captcha", re: /\b(captcha|recaptcha|hcaptcha|are you a robot|verify you are human)\b/i },
	{ signal: "waf", re: /\b(web application firewall|blocked by|access denied|cloudflare|akamai|mod_security|406 not acceptable|request blocked)\b/i },
	{ signal: "rate_limited", re: /\b(rate ?limit|too many requests|429|slow down|retry-after)\b/i },
	{ signal: "account_locked", re: /\b(account (is )?locked|account (is )?disabled|too many (failed )?login|temporarily locked)\b/i },
	{ signal: "unresponsive", re: /\b(connection refused|connection timed out|could not connect|host (is )?(down|unreachable)|no route to host|ETIMEDOUT|ECONNREFUSED)\b/i },
];

export function detectUnhealthy(text: string): string | null {
	for (const { signal, re } of UNHEALTHY_SIGNALS) {
		if (re.test(text)) {
			return signal;
		}
	}
	return null;
}

/** How many times a proposed command has already been tried, exactly, in a
 * recent window. Genuine repetition — a DIFFERENT command (a bypass/evasion
 * mutation, §6.5.2) does NOT match, so it counts as progress, not a stall. */
export function repeatCount(command: string, recentCommands: string[]): number {
	const norm = command.trim();
	return recentCommands.filter((c) => c.trim() === norm).length;
}

/**
 * Per-class TRY BUDGET (§10.5, run-2/run-3 lesson). Some attack classes are
 * high-cost and low-yield when they don't hit fast: a SINGLE `hydra` call fired
 * ~173k requests in run-2, and run-3 spent ~7 hydra runs — the maxToolCalls cap
 * never catches a per-request blow-up, and each brute/crack call is a NOVEL
 * command so stuck-detection reads it as progress, not a stall. So the harness
 * caps how many attempts of each expensive class an engagement may spend before
 * it MUST pivot — the deterministic version of the pivot the operator had to
 * force by hand. Content discovery (gobuster/ffuf dir brute) is the PRODUCTIVE
 * enumeration the web skill wants, so it gets a high ceiling, not a tight one.
 */
export type AttackClass = "brute_auth" | "hash_crack" | "web_fuzz";

// First match wins; brute_auth is tested before web_fuzz so an auth brute via a
// fuzzer (ffuf/wfuzz with a login/data/Authorization payload) counts as brute,
// not content discovery.
const ATTACK_CLASS_SIGNATURES: Array<{ cls: AttackClass; re: RegExp }> = [
	{ cls: "brute_auth", re: /\b(hydra|medusa|ncrack|patator|crowbar|thc-hydra)\b/i },
	{ cls: "brute_auth", re: /\b(ffuf|wfuzz)\b[^\n]*(?:-d\b|--data|Authorization|\blogin\b|passw|-x\s+POST|-X\s+POST)/i },
	{ cls: "hash_crack", re: /\b(john|hashcat)\b/i },
	{ cls: "web_fuzz", re: /\b(gobuster|dirb|dirbuster|feroxbuster|ffuf|wfuzz)\b/i },
];

export function classifyAttack(command: string): AttackClass | null {
	for (const { cls, re } of ATTACK_CLASS_SIGNATURES) {
		if (re.test(command)) return cls;
	}
	return null;
}

export type TryBudget = Record<AttackClass, number>;

export const DEFAULT_TRY_BUDGET: TryBudget = {
	brute_auth: 5, // run-3 spent ~7 hydra runs before the operator forced a pivot
	hash_crack: 4, // no GPU here: rockyou + rockyou-rules per hash, then it's dead
	web_fuzz: 40, // enumeration is productive — a high ceiling, not a tight one
};

export interface TryBudgetInput {
	/** The command about to run. */
	command: string;
	/** Every command already run for this target (the attempts ledger). */
	priorCommands: string[];
	budget: TryBudget;
	/** A validated code-execution foothold exists — changes the pivot guidance
	 * (post-foothold cracking is legitimate privesc, pre-foothold brute is not). */
	hasValidatedFoothold: boolean;
}

export type BudgetVerdict = { over: false } | { over: true; cls: AttackClass; spent: number; reason: string; guidance: string };

export function checkTryBudget(input: TryBudgetInput): BudgetVerdict {
	const cls = classifyAttack(input.command);
	if (!cls) return { over: false };
	const spent = input.priorCommands.filter((c) => classifyAttack(c) === cls).length;
	const limit = input.budget[cls];
	if (spent < limit) return { over: false };
	const pivotHint =
		cls === "brute_auth"
			? input.hasValidatedFoothold
				? "you already have a foothold — brute-forcing more auth is off-path; work privilege escalation instead"
				: "map more unauthenticated surface (content discovery, other services/ports) before more auth brute — the way in is rarely a guessed password"
			: cls === "hash_crack"
				? "there is no GPU here; if rockyou + rules did not crack it, the hash is not the way — read the plaintext from a config/backup/history with the access you have, or pivot to another vector"
				: "content discovery is exhausted for this wordlist — escalate the wordlist deliberately or pivot to a different service/technique";
	return {
		over: true,
		cls,
		spent,
		reason: `try-budget for '${cls}' exhausted (${spent}/${limit} attempts)`,
		guidance: `Try-budget for '${cls}' reached (${spent}/${limit}). This class is not producing progress — ${pivotHint}. This call is blocked to force a pivot (§10.5); a genuinely different technique is the way forward, not another '${cls}' attempt.`,
	};
}

export interface StuckInput {
	command: string;
	recentCommands: string[];
	repeatThreshold: number;
	/** Nodes at the start of the window vs now — no growth is a stall signal. */
	nodeCountAtWindowStart: number;
	nodeCountNow: number;
}

export type StuckVerdict =
	| { stuck: false }
	| { stuck: true; reason: string; signal: "repeated_call" | "no_new_nodes" };

export function detectStuck(input: StuckInput): StuckVerdict {
	const repeats = repeatCount(input.command, input.recentCommands);
	if (repeats >= input.repeatThreshold) {
		return {
			stuck: true,
			signal: "repeated_call",
			reason: `the same tool call has been repeated ${repeats}x with no new result`,
		};
	}
	// A NOVEL proposed call — one not already in the recent window — is a new
	// technique/pivot (a bypass/evasion attempt included), which §6.5.2 counts
	// as progress. Never treat a fresh approach as a stall, even if the prior
	// window was circling and the tree hasn't grown yet.
	const isNovel = !input.recentCommands.some((c) => c.trim() === input.command.trim());
	if (isNovel) {
		return { stuck: false };
	}

	// No new nodes AND low variation: the tree has stopped growing while the
	// agent re-proposes calls from a small set it is circling.
	const distinct = new Set(input.recentCommands.map((c) => c.trim())).size;
	const lowVariation = distinct <= Math.floor(input.recentCommands.length / 2);
	if (
		input.recentCommands.length >= input.repeatThreshold &&
		input.nodeCountNow <= input.nodeCountAtWindowStart &&
		lowVariation
	) {
		return {
			stuck: true,
			signal: "no_new_nodes",
			reason: `no new investigation nodes while circling ${distinct} call(s) over the last ${input.recentCommands.length} attempts`,
		};
	}
	return { stuck: false };
}

/**
 * No-PROGRESS detection (board fix, Jangow run). `detectStuck` keys on command
 * SHAPE (repeats / low variation), so it is blind to the failure that actually
 * happened: the agent fired a stream of NOVEL commands (fresh pty.fork scripts)
 * that produced no new ledger fact — 30 minutes of motion, zero progress, and
 * every shape-based guard read it as fine.
 *
 * This is the fact-based backstop: a "progress fingerprint" of the LEDGER (how
 * far we've reached + how many candidates/validated/creds/root exist). When the
 * fingerprint does not change across a window of tool calls, the agent is busy
 * but not advancing — nudge it to the untried checklist, escalate if it
 * persists. It is orthogonal to detectStuck (which needs low command variation)
 * and fires precisely on novel-activity-without-a-new-fact.
 */
export interface ProgressFingerprint {
	/** milestoneRank(reached) — recon < surface < candidate < foothold < root. */
	milestone: number;
	candidates: number;
	validated: number;
	creds: number;
	/** 1 once a privilege_escalation finding is validated, else 0. */
	rootValidated: number;
}

export function sameProgress(a: ProgressFingerprint, b: ProgressFingerprint): boolean {
	return a.milestone === b.milestone && a.candidates === b.candidates && a.validated === b.validated && a.creds === b.creds && a.rootValidated === b.rootValidated;
}

export interface NoProgressState {
	last: ProgressFingerprint | null;
	/** Tool calls observed since the fingerprint last CHANGED. */
	callsSinceChange: number;
}

export const INITIAL_NO_PROGRESS_STATE: NoProgressState = { last: null, callsSinceChange: 0 };

/** Fold a new observation into the state: reset the counter on any change,
 * otherwise increment. Pure — the hook holds the state across calls. */
export function updateNoProgress(state: NoProgressState, current: ProgressFingerprint): NoProgressState {
	if (state.last === null || !sameProgress(state.last, current)) {
		return { last: current, callsSinceChange: 0 };
	}
	return { last: state.last, callsSinceChange: state.callsSinceChange + 1 };
}

export type NoProgressVerdict = { stalled: false } | { stalled: true; calls: number; reason: string };

/** Stalled when the fingerprint has been unchanged for `window` consecutive
 * calls. `window` is generous (a legit linpeas + sudo -l + SUID sweep is well
 * under it and, more importantly, each of those produces a new node/fact that
 * resets the counter). */
export function noProgressStalled(state: NoProgressState, window: number): NoProgressVerdict {
	if (state.callsSinceChange >= window) {
		return { stalled: true, calls: state.callsSinceChange, reason: `no new finding, credential, validated status, or phase advance in ${state.callsSinceChange} tool calls` };
	}
	return { stalled: false };
}
