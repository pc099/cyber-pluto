/**
 * The Pluto launcher — a single, typed entrypoint.
 *
 * Pluto is NOT a bash wrapper that assembles a harness out of `-e` flags. The
 * harness DEFINITION (extension stack, runtime-skill catalog, reasoning
 * defaults) lives in `.pi/settings.json` and is loaded by Pi itself when it
 * runs in this repo (trusted with `-a`). This launcher only turns an operator's
 * intent into an ENGAGEMENT: it resolves scope, sets the `PLUTO_*` env, injects
 * the per-engagement briefing, and starts Pi — once, through one code path, for
 * both interactive and headless (`--headless`) runs.
 *
 * `buildPlan()` is pure (argv -> LaunchPlan) so the assembly is unit-tested,
 * not left as untestable shell.
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const PI_CLI = "pi/pi/packages/coding-agent/dist/bundle/cli.js";

export interface LaunchPlan {
	target: string;
	scopeHosts: string[];
	scopeCsv: string;
	label: string;
	provider?: string;
	model?: string;
	attackProvider?: string;
	attackModel?: string;
	maxCalls: number;
	maxWall: number;
	maxTokens: number;
	objective: string;
	tunnel: boolean;
	program?: string;
	trafficId?: string;
	rate?: string;
	headless: boolean;
	dryRun: boolean;
	env: Record<string, string>;
	cliArgs: string[];
	briefing: string;
}

export type ParseResult = { kind: "plan"; plan: LaunchPlan } | { kind: "help" } | { kind: "error"; message: string };

function normalizeScope(raw: string): string[] {
	return raw
		.split(/[,\s]+/)
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}

export function buildPlan(argv: string[]): ParseResult {
	let scope = "";
	let scopeFile = "";
	let target = "";
	let provider: string | undefined;
	let model: string | undefined;
	let attackProvider: string | undefined;
	let attackModel: string | undefined;
	let maxCalls = 200;
	let maxWall = 3600;
	let maxTokens = 4_000_000;
	let label = "";
	let tunnel = false;
	let dryRun = false;
	let headless = false;
	let program: string | undefined;
	let trafficId: string | undefined;
	let rate: string | undefined;
	const objectiveParts: string[] = [];

	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === undefined) continue;
		const next = (): string => {
			const v = argv[++i];
			if (v === undefined) throw new Error(`missing value for ${a}`);
			return v;
		};
		try {
			switch (a) {
				case "--scope": scope = next(); break;
				case "--scope-file": scopeFile = next(); break;
				case "--provider": provider = next(); break;
				case "--model": model = next(); break;
				case "--attack-provider": attackProvider = next(); break;
				case "--attack-model": attackModel = next(); break;
				case "--max-calls": maxCalls = Number(next()); break;
				case "--max-wall": maxWall = Number(next()); break;
				case "--max-tokens": maxTokens = Number(next()); break;
				case "--no-cap": maxCalls = 0; maxWall = 0; maxTokens = 0; break;
				case "--label": label = next(); break;
				case "--tunnel": tunnel = true; break;
				case "--program": program = next(); break;
				case "--traffic-id": trafficId = next(); break;
				case "--rate": rate = next(); break;
				case "--headless": case "--auto": headless = true; break;
				case "--dry-run": dryRun = true; break;
				case "-h": case "--help": return { kind: "help" };
				default:
					if (a.startsWith("-")) return { kind: "error", message: `unknown option: ${a}` };
					if (!target) target = a; else objectiveParts.push(a);
			}
		} catch (err) {
			return { kind: "error", message: err instanceof Error ? err.message : String(err) };
		}
	}

	const scopeHosts: string[] = [];
	if (target) scopeHosts.push(target);
	if (scope) scopeHosts.push(...normalizeScope(scope));
	if (scopeFile) {
		if (!existsSync(scopeFile)) return { kind: "error", message: `scope file not found: ${scopeFile}` };
		for (let line of readFileSync(scopeFile, "utf8").split("\n")) {
			line = line.replace(/#.*$/, "").trim().replace(/^[-*]\s*/, "").replace(/^host:\s*/i, "").trim();
			if (line) scopeHosts.push(line);
		}
	}
	const first = scopeHosts[0];
	if (first === undefined) return { kind: "error", message: "a target (or --scope/--scope-file) is required" };
	if (!target) target = first;
	if (!label) label = `engagement-${target.replace(/[^a-zA-Z0-9]/g, "-").replace(/-+$/, "")}`;

	const scopeCsv = [...new Set(scopeHosts)].join(",");
	const objective = objectiveParts.join(" ");

	const tunnelNote = tunnel ? " Traffic is routed through a TCP-only tunnel, so use 'nmap -sT' (TCP connect), not the default SYN scan." : "";
	const bbNote = trafficId || program
		? ` This is a BUG-BOUNTY engagement${program ? ` for program '${program}'` : ""}. Compliance is mandatory: include the traffic-identification header${trafficId ? ` '${trafficId}'` : ""} on EVERY HTTP request (curl -H, wget --header, sqlmap --headers, ffuf -H)${rate ? `, and respect a rate limit of ${rate} request(s)/second` : ""}. Prove impact minimally and never exfiltrate real data. NOTHING is submitted without the operator's explicit approval.`
		: "";

	const briefing = [
		"You are Pluto, an AUTHORIZED autonomous penetration-testing harness on a live engagement.",
		`In-scope hosts: ${scopeCsv}. Primary target: ${target}. Stay strictly within scope — the red-lines gate blocks any out-of-scope or prohibited action before it runs, and going out of scope forfeits safe harbor.`,
		"Two-gate discipline: a finding is only a fact once a deterministic validator reproduces it (use the validate_* tools) — never act on a 'candidate' as though 'validated'; and nothing is ever submitted externally without explicit human approval.",
		`Everything you do is logged. The operator can halt you at any instant (kill switch).${tunnelNote}${bbNote}`,
		"Adapt to the target: the instant you identify the engagement class and your current tools do not fit it, call provision_capability(domain) to install that domain's toolset and load its doctrine BEFORE diving in (a raw/networked binary => 'binary-exploitation'; a cipher/RSA challenge => 'cryptography'; a pcap/dump => 'forensics'). Use list_capabilities if unsure. Do not hand-derive what a tool measures — provision the tool and measure it.",
		`Work the engagement: recon, grow the investigation tree, validate findings through Gate 1, recover access, and report — consulting the knowledge base and runtime skills as you go. Record any credentials you recover with the record_credential tool.${objective ? ` Operator objective: ${objective}` : ""}`,
	].join("\n");

	// Env: the per-engagement dynamics (the harness stack itself comes from .pi/settings.json).
	const env: Record<string, string> = {
		PLUTO_TARGET_LABEL: label,
		PLUTO_TARGET_HOST: target,
		PLUTO_SCOPE_HOSTS: scopeCsv,
		PLUTO_MAX_TOOL_CALLS: String(maxCalls),
		PLUTO_MAX_WALLCLOCK_S: String(maxWall),
		PLUTO_MAX_TOKENS: String(maxTokens),
		PLUTO_SUBAGENT_PROVIDER: provider ?? "anthropic",
		// Per-target state-DB isolation: each target gets its own pluto.db, so
		// targets never share one ledger (which accumulated stale-target rows).
		// Control files, logs, and evidence stay at the repo root — run one
		// engagement at a time (see state/db.ts stateDir docstring).
		PLUTO_STATE_DIR: `engagements/${label}/state`,
	};
	if (model) env.PLUTO_SUBAGENT_MODEL = model;
	if (attackProvider) env.PLUTO_ATTACK_PROVIDER = attackProvider;
	if (attackModel) env.PLUTO_ATTACK_MODEL = attackModel;
	if (program) env.PLUTO_PROGRAM = program;
	if (trafficId) env.PLUTO_TRAFFIC_ID = trafficId;
	if (rate) env.PLUTO_RATE_LIMIT = rate;

	// CLI args: -a trusts the repo profile (.pi/settings.json = the stack); the
	// launcher passes ONLY per-engagement dynamics, never the extension/skill set.
	const cliArgs = [PI_CLI, "-a", "--no-context-files"];
	if (provider) cliArgs.push("--provider", provider);
	if (model) cliArgs.push("--model", model);
	cliArgs.push("--append-system-prompt", briefing);
	if (headless) {
		env.PLUTO_HEADLESS = "1"; // lifecycle turns an environmental pause into a terminal stop (no operator to /resume)
		cliArgs.push("-p", `Begin the engagement against ${target} now. Start with recon.`);
	}

	return {
		kind: "plan",
		plan: {
			target, scopeHosts, scopeCsv, label, provider, model, attackProvider, attackModel,
			maxCalls, maxWall, maxTokens, objective, tunnel, program, trafficId, rate, headless, dryRun,
			env, cliArgs, briefing,
		},
	};
}

const BANNER = `
   ______      __              ____  __      __
  / ____/_  __/ /_  ___  _____/ __ \\/ /_  __/ /_____
 / /   / / / / __ \\/ _ \\/ ___/ /_/ / / / / / __/ __ \\
/ /___/ /_/ / /_/ /  __/ /  / ____/ / /_/ / /_/ /_/ /
\\____/\\__, /_.___/\\___/_/  /_/   /_/\\__,_/\\__/\\____/
     /____/   autonomous cybersecurity testing harness

           two gates · red-lines · no PoC, no finding
`;

const HELP = `Usage: cyberpluto [TARGET] [OBJECTIVE...] [options]

  The harness stack is defined in .pi/settings.json (loaded by Pi, trusted with -a).
  This launcher only starts an ENGAGEMENT against a target.

Options:
  --scope LIST         Comma/space in-scope hosts (adds to TARGET)
  --scope-file FILE    Read in-scope hosts from a file
  --provider NAME      LLM provider (default from profile: anthropic)
  --model NAME         Reasoning model (default from profile)
  --attack-provider P  Provider for the exploitation phase (phase routing)
  --attack-model NAME  Model for the exploitation phase
  --max-calls N        Tool-call hard cap (default 200; 0 = unlimited)
  --max-wall SECONDS   Active wall-clock hard cap (default 3600; 0 = unlimited)
  --max-tokens N       Context-token ceiling — a conservative over-estimate of
                       spend, not a bill (default 4000000; 0 = unlimited)
  --no-cap             Remove all hard caps
  --label NAME         Engagement label
  --tunnel             Brief Pluto to use TCP-connect scans
  --program / --traffic-id / --rate   Bug-bounty compliance
  --headless           Run autonomously (no interactive shell)
  --dry-run            Print the resolved plan and exit
  -h, --help           This help`;

function repoRoot(): string {
	return process.cwd();
}

async function main(): Promise<void> {
	const res = buildPlan(process.argv.slice(2));
	if (res.kind === "help") { process.stdout.write(`${BANNER}\n${HELP}\n`); return; }
	if (res.kind === "error") { process.stderr.write(`cyberpluto: ${res.message}\n\n${HELP}\n`); process.exitCode = 1; return; }

	const plan = res.plan;
	const root = repoRoot();
	if (!existsSync(join(root, PI_CLI))) {
		process.stderr.write(`Pi is not built. Run: cd pi/pi && npm install --ignore-scripts && npm run build\n`);
		process.exitCode = 1; return;
	}
	if (!existsSync(join(root, "extensions/dist/tool-log/index.js"))) {
		process.stderr.write(`Extensions not built. Run: cd extensions && npm run build\n`);
		process.exitCode = 1; return;
	}

	process.stdout.write(BANNER);
	const capsCalls = plan.maxCalls === 0 ? "unlimited calls" : `${plan.maxCalls} calls`;
	const capsWall = plan.maxWall === 0 ? "unlimited wall" : `${plan.maxWall}s wall`;
	const capsTok = plan.maxTokens === 0 ? "unlimited tokens" : `~${(plan.maxTokens / 1e6).toFixed(1)}M ctx-tokens (est.)`;
	process.stdout.write(
		`  target      ${plan.target}\n` +
		`  scope       ${plan.scopeCsv}\n` +
		`  provider    ${plan.provider ?? "(profile default)"}\n` +
		`  model       ${plan.model ?? "(profile default)"}\n` +
		`  caps        ${capsCalls} · ${capsWall} · ${capsTok}\n` +
		`  mode        ${plan.headless ? "headless (autonomous)" : "interactive shell"}\n` +
		`  profile     .pi/settings.json — the harness stack (trusted with -a)\n` +
		`  label       ${plan.label}\n` +
		(plan.attackProvider || plan.attackModel ? `  attack      ${plan.attackProvider ?? plan.provider ?? "default"} / ${plan.attackModel ?? plan.model ?? "default"}\n` : "") +
		`  kill switch touch ${join(root, "state/KILL_SWITCH")}\n` +
		`  ---------------------------------------------------------------\n` +
		`  Console: /pluto menu · /status /findings /nodes /creds · /approve (Gate 2) · /kill\n\n`,
	);

	if (plan.dryRun) {
		process.stdout.write(`[dry-run] env: ${Object.entries(plan.env).map(([k, v]) => `${k}=${v}`).join(" ")}\n`);
		process.stdout.write(`[dry-run] launch: node ${plan.cliArgs.map((x) => (x.includes(" ") ? `'${x.slice(0, 40)}…'` : x)).join(" ")}\n`);
		return;
	}

	const child = spawn("node", plan.cliArgs, {
		cwd: root,
		stdio: "inherit",
		env: { ...process.env, ...plan.env },
	});
	child.on("exit", (code) => { process.exitCode = code ?? 0; });
}

// Only run main when invoked directly (not when imported by tests).
if (process.argv[1] && process.argv[1].endsWith("launcher/index.js")) {
	void main();
}
