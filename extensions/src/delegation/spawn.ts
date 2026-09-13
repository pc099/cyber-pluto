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
 * extension set begins with red-lines + tool-log. A sub-agent therefore cannot
 * be spawned without the §10.4 gate and the audit log — the propagation is
 * structural, enforced here in one place, not left to each call site to
 * remember. `specialistExtensions` is the single chokepoint.
 */
import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const CLI_REL = "pi/pi/packages/coding-agent/dist/bundle/cli.js";
// A sub-agent is a full cold-start Pi process making its own LLM calls, and a
// delegation may itself run inside another sub-agent, so allow generous
// headroom before treating a slow specialist as a failure.
const DEFAULT_TIMEOUT_MS = 600000;

function ext(name: string): string {
	return `extensions/src/${name}/index.ts`;
}

/** Every sub-agent gets these, first, no matter the specialist — the safety
 * gate and the audit log are non-negotiable and cannot be opted out of. */
const ALWAYS: readonly string[] = [ext("red-lines"), ext("tool-log")];

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

/** The extension set for a specialist — ALWAYS (red-lines + tool-log) plus the
 * specialist's own tools. Unknown specialists fall back to analyst (safe:
 * red-lines + tool-log, no offensive tools). */
export function specialistExtensions(specialist: string): string[] {
	const extra = SPECIALIST_EXTRA[specialist] ?? SPECIALIST_EXTRA.analyst ?? [];
	return [...ALWAYS, ...extra];
}

export function subAgentModel(): string {
	return process.env["PLUTO_SUBAGENT_MODEL"] ?? "claude-haiku-4-5";
}

export function buildSubAgentArgs(opts: { model: string; prompt: string; extensions: string[] }): string[] {
	const args = [CLI_REL, "--provider", "anthropic", "--model", opts.model, "--no-session", "-p", opts.prompt];
	for (const e of opts.extensions) {
		args.push("-e", e);
	}
	return args;
}

export interface SubAgentRun {
	specialist: string;
	extensions: string[];
	model: string;
	output: string;
	stderr: string;
}

export async function spawnSubAgent(
	cwd: string,
	opts: { specialist: string; prompt: string; model?: string; timeoutMs?: number },
): Promise<SubAgentRun> {
	const model = opts.model ?? subAgentModel();
	const extensions = specialistExtensions(opts.specialist);
	const args = buildSubAgentArgs({ model, prompt: opts.prompt, extensions });
	const { stdout, stderr } = await execFileAsync("node", args, {
		cwd,
		env: { ...process.env },
		timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
		maxBuffer: 8 * 1024 * 1024,
	});
	return { specialist: opts.specialist, extensions, model, output: stdout.trim(), stderr: stderr.trim() };
}
