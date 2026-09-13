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
}

export type CapVerdict = { stop: true; reason: string; kind: "tool_calls" | "wall_clock" } | { stop: false };

export function checkHardCaps(toolCallCount: number, elapsedSeconds: number, caps: HardCaps): CapVerdict {
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
