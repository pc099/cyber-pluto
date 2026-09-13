/**
 * The red-lines pre-execution check (Architecture §10.4).
 *
 * Pure and deterministic: given a proposed tool invocation and the current
 * scope context, it returns an allow/block decision. No side effects, no LLM,
 * no I/O — so it is trivially unit-testable and identical whether it runs in
 * the main reasoning core or a delegated sub-agent (§6.4). The enforcement
 * hook (index.ts) is the only thing that turns a block decision into an
 * actually-refused tool call; keeping the decision pure is what lets the same
 * check propagate everywhere without carrying state.
 *
 * The result is a discriminated union (typescript-patterns): the caller is
 * forced to handle the blocked case — there is no way to read "allowed"
 * without also confronting "not allowed".
 */
import { RED_LINE_RULES, type RedLineCategory, type RedLineContext, type RedLineRule, type ToolInvocation } from "./rules.js";

export type RedLineDecision =
	| { allowed: true }
	| { allowed: false; ruleId: string; category: RedLineCategory; reason: string };

export function checkRedLines(inv: ToolInvocation, ctx: RedLineContext): RedLineDecision {
	for (const rule of RED_LINE_RULES) {
		const reason = safeEvaluate(rule, inv, ctx);
		if (reason !== null) {
			return { allowed: false, ruleId: rule.id, category: rule.category, reason };
		}
	}
	return { allowed: true };
}

/** A rule throwing must never let a tool call through by accident — a rule
 * fault fails toward blocking (safety gate), surfacing the fault as the
 * reason so it is visible rather than silently swallowed. */
function safeEvaluate(rule: RedLineRule, inv: ToolInvocation, ctx: RedLineContext): string | null {
	try {
		return rule.evaluate(inv, ctx);
	} catch (err) {
		return `red-line rule '${rule.id}' errored while evaluating; blocking to fail safe: ${
			err instanceof Error ? err.message : String(err)
		}`;
	}
}

/** Normalize a Pi tool-call into the invocation shape the ruleset scans. */
export function toInvocation(toolName: string, input: unknown): ToolInvocation {
	let commandText: string;
	if (toolName === "bash" && input && typeof input === "object" && "command" in input) {
		commandText = String((input as { command: unknown }).command);
	} else {
		try {
			commandText = JSON.stringify(input);
		} catch {
			commandText = String(input);
		}
	}
	return { toolName, input, commandText };
}
