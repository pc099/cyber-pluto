/**
 * Sub-agent spawning (Architecture §6.4). Pi has no native sub-agents, so a
 * delegation is literally a separate `pi` PROCESS with its own isolated
 * context window (§6.3/§6.4). This module builds and runs that process.
 *
 * Isolation: each sub-agent is its own OS process, `--no-session` (ephemeral,
 * never touches the parent's session), and its own extension realm. The parent
 * sees only the sub-agent's final stdout — none of its intermediate context
 * leaks back. The sub-agent shares the workspace cwd, so it reaches the same
 * `state/pluto.db` (shared engagement) and, critically, the same gates.
 *
 * Red-lines propagation (§10.4, the Session 5 contract): EVERY specialist's
 * extension set begins with binding, red-lines, tool-log and lifecycle. A child
 * inherits its parent's engagement association and interruption constraints,
 * and cannot be spawned without the §10.4 gate and the audit log. Propagation is
 * structural, enforced here in one place, not left to each call site to
 * remember. `specialistExtensions` is the single chokepoint.
 */
import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { getActiveBinding, bindingPath, assertParentMayRun } from "../state/session-binding.js";
import { getProviderHold } from "../lifecycle/provider-outcome.js";

const execFileAsync = promisify(execFile);

const CLI_REL = "pi/pi/packages/coding-agent/dist/bundle/cli.js";
// A sub-agent is a full cold-start Pi process making its own LLM calls, and a
// delegation may itself run inside another sub-agent, so allow generous
// headroom before treating a slow specialist as a failure.
const DEFAULT_TIMEOUT_MS = 600000;

function ext(name: string): string {
	return `extensions/src/${name}/index.ts`;
}

/** Every specialist gets continuity, scope, audit and interruption guards first. */
const ALWAYS: readonly string[] = [ext("engagement-binding"), ext("red-lines"), ext("tool-log"), ext("lifecycle")];

const SPECIALIST_EXTRA: Record<string, string[]> = {
	// Full-handoff exploitation specialist: owns a validated finding through
	// to a PoC (§2.3.2) — needs the exploitation + validation tools.
	exploitation: [ext("exploit"), ext("validators")],
	// Recon specialist.
	recon: [ext("recon")],
	// Bounded analyst/consultant (agent-as-tool default): reasoning only, no
	// extra offensive tools — it advises, it does not act.
	analyst: [],
};

export type Specialist = keyof typeof SPECIALIST_EXTRA;

export function knownSpecialist(name: string): name is Specialist {
	return name in SPECIALIST_EXTRA;
}

/** The extension set for a specialist — ALWAYS guards plus the
 * specialist's own tools. Unknown specialists fall back to analyst (safe:
 * red-lines + tool-log, no offensive tools). */
export function specialistExtensions(specialist: string): string[] {
	const extra = SPECIALIST_EXTRA[specialist] ?? SPECIALIST_EXTRA.analyst ?? [];
	return [...ALWAYS, ...extra];
}

export interface SubAgentTarget {
	provider: string;
	model: string;
}

/**
 * Phase-based model routing (§6.4). A delegation's specialist IS the engagement
 * phase, so the model is chosen per specialist:
 *
 *  - The `exploitation` specialist can use an operator-configured model via
 *    PLUTO_ATTACK_PROVIDER / PLUTO_ATTACK_MODEL for its declared task. This
 *    configuration is not an automatic fallback after a provider policy block;
 *    the parent's persisted interruption guard still applies before spawning.
 *  - recon / analyst (and the orchestrator) stay on the main provider
 *    (PLUTO_SUBAGENT_PROVIDER / PLUTO_SUBAGENT_MODEL).
 *
 * Defaults keep EVERY specialist on the main provider, so routing only diverges
 * once an attack model is explicitly configured — no behavior change otherwise.
 * The switch carries no gate change: red-lines + tool-log are still loaded into
 * the exploitation sub-agent (specialistExtensions/ALWAYS), so a different,
 * configured model on the attack phase remains bounded by the §10.4 gate.
 */
export function subAgentTarget(specialist: string): SubAgentTarget {
	const mainProvider = process.env["PLUTO_SUBAGENT_PROVIDER"] ?? "openai-codex";
	const mainModel = process.env["PLUTO_SUBAGENT_MODEL"] ?? "gpt-5.5";
	if (specialist === "exploitation") {
		return {
			provider: process.env["PLUTO_ATTACK_PROVIDER"] ?? mainProvider,
			model: process.env["PLUTO_ATTACK_MODEL"] ?? mainModel,
		};
	}
	return { provider: mainProvider, model: mainModel };
}

/** Back-compat: the main-provider model id. */
export function subAgentModel(): string {
	return subAgentTarget("analyst").model;
}

export function buildSubAgentArgs(opts: { provider?: string; model: string; prompt: string; extensions: string[] }): string[] {
	const args = [CLI_REL, "--provider", opts.provider ?? "openai-codex", "--model", opts.model, "--no-session", "-p", opts.prompt];
	for (const e of opts.extensions) {
		args.push("-e", e);
	}
	return args;
}

export interface SubAgentRun {
	specialist: string;
	extensions: string[];
	provider: string;
	model: string;
	output: string;
	stderr: string;
}

export async function spawnSubAgent(
	cwd: string,
	opts: { specialist: string; prompt: string; provider?: string; model?: string; timeoutMs?: number },
): Promise<SubAgentRun> {
	const binding = getActiveBinding(cwd);
	assertParentMayRun(binding, cwd);
	const target = subAgentTarget(opts.specialist);
	const provider = opts.provider ?? target.provider;
	const model = opts.model ?? target.model;
	const extensions = specialistExtensions(opts.specialist);
	const args = buildSubAgentArgs({ provider, model, prompt: opts.prompt, extensions });
	const { stdout, stderr } = await execFileAsync("node", args, {
		cwd,
		env: buildSubAgentEnv(cwd),
		timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
		maxBuffer: 8 * 1024 * 1024,
	});
	return { specialist: opts.specialist, extensions, provider, model, output: stdout.trim(), stderr: stderr.trim() };
}

/** Ephemeral children must explicitly inherit a validated parent descriptor. */
export function buildSubAgentEnv(cwd: string, env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
	const binding = getActiveBinding(cwd, env);
	assertParentMayRun(binding, cwd);
	if (env.PLUTO_DELEGATE_ID) {
		const ownHold = getProviderHold({ sessionId: env.PLUTO_DELEGATE_ID, sessionFile: `${binding.sessionFile}.delegate-${env.PLUTO_DELEGATE_ID}` });
		if (ownHold.blocked) throw new Error(`Delegation blocked: calling specialist is held (${ownHold.reason})`);
	}
	const child: NodeJS.ProcessEnv = { ...env, PLUTO_PARENT_BINDING_PATH: bindingPath(binding.sessionFile), PLUTO_DELEGATE_ID: randomUUID() };
	delete child.PLUTO_ACTIVE_SESSION_FILE;
	delete child.PLUTO_ACTIVE_SESSION_ID;
	delete child.PLUTO_ACTIVE_BINDING_PATH;
	delete child.PLUTO_ADOPT_SESSION;
	return child;
}
