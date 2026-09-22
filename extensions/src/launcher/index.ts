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
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { findCapability } from "../capabilities/manifest.js";

const PI_CLI = "pi/pi/packages/coding-agent/dist/bundle/cli.js";

/** Launch-time STRUCTURAL provisioning (Decision 0005, Increment 3). The first
 * run never called provision_capability despite the briefing, hand-rolled curl,
 * and burned the token cap. So the launcher itself verifies the declared
 * engagement domain's toolset is present and installs the manifest-whitelisted
 * packages (root only) BEFORE handoff — a briefing nudge is the lever that
 * already failed. Verify-first: if the tools are baked/installed, nothing runs. */
function provisionDomain(root: string, domain: string): void {
	const cap = findCapability(domain);
	if (!cap) {
		process.stderr.write(`  provisioning: unknown domain '${domain}' — skipping (see list_capabilities).\n`);
		return;
	}
	const verifyOk = (): boolean => spawnSync("bash", ["-c", cap.verify], { cwd: root, stdio: "ignore" }).status === 0;
	if (verifyOk()) {
		process.stdout.write(`  provisioning  '${domain}' toolset present ✓\n`);
		return;
	}
	if (process.getuid?.() !== 0) {
		process.stderr.write(
			`  provisioning: '${domain}' toolset MISSING and not root — install manually: apt-get install -y ${cap.apt.join(" ")}${cap.pip.length ? ` && pip install ${cap.pip.join(" ")}` : ""}\n`,
		);
		return;
	}
	process.stdout.write(`  provisioning  installing '${domain}' toolset: ${[...cap.apt, ...cap.pip].join(", ")}\n`);
	if (cap.apt.length) spawnSync("apt-get", ["install", "-y", ...cap.apt], { cwd: root, stdio: "inherit", env: { ...process.env, DEBIAN_FRONTEND: "noninteractive" } });
	if (cap.pip.length) spawnSync("pip", ["install", "--break-system-packages", ...cap.pip], { cwd: root, stdio: "inherit" });
	process.stdout.write(verifyOk() ? `  provisioning  '${domain}' verified ✓\n` : `  provisioning: '${domain}' still fails verify — continuing; the agent may lack tools.\n`);
}
// Gate-1 privileged promotion signer (Item 0). The private key lives OUTSIDE the
// pluto-readable harness tree (setup.sh installs it root-only); the daemon holds
// it and the confined agent reaches it only through the socket + client.
const PROMOTION_PRIVKEY_DEFAULT = "/etc/cyber-pluto/promotion_ed25519.key";
const PROMOTION_DAEMON_JS = "extensions/dist/state/promotion-sign-daemon.js";
const PROMOTION_CLIENT_JS = "extensions/dist/state/promotion-sign-client.js";

/** Block (without async) until a path exists or the timeout elapses — used to
 * wait for the signing daemon's socket before starting the confined agent. */
function waitForPathSync(path: string, timeoutMs = 5000): boolean {
	const deadline = Date.now() + timeoutMs;
	const pause = new Int32Array(new SharedArrayBuffer(4));
	while (Date.now() < deadline) {
		if (existsSync(path)) return true;
		Atomics.wait(pause, 0, 0, 40);
	}
	return existsSync(path);
}

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
	sandbox: boolean;
	dryRun: boolean;
	/** Operator-declared engagement class (default "web"). Drives launch-time
	 * provisioning and PLUTO_ENGAGEMENT_CLASS (e.g. the forensics red-line exemption). */
	domain: string;
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
	let sandbox = false;
	let domain = "web";
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
				case "--target": case "--host": target = next(); break;
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
				case "--sandbox": sandbox = true; break;
				case "--domain": domain = next(); break;
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

	// Catch the common mis-invocation `pluto init-engagement …`: Cyber Pluto has
	// NO subcommands — the target is the first argument (or --target). A
	// subcommand-style first word would otherwise become a bogus target and
	// red-line every real access.
	const SUBCOMMAND_MISTAKES = new Set([
		"init-engagement", "init", "engage", "engagement", "start", "run", "scan", "new", "create", "begin",
	]);
	if (target && SUBCOMMAND_MISTAKES.has(target.toLowerCase())) {
		return {
			kind: "error",
			message: `'${target}' is not a target host — Cyber Pluto has no subcommands. Pass the target as the first argument (or with --target):\n    pluto <target-ip-or-host> "<objective>"\n  e.g.  pluto 192.168.122.68 "find and exploit web vulns, escalate to root, capture the flags"`,
		};
	}
	// Junk scope tokens some operators reach for ("full"/"all") aren't hosts; drop
	// them so they don't pollute the scope set (the target itself is in scope).
	if (scope) scope = normalizeScope(scope).filter((s) => !["full", "all", "any", "*"].includes(s.toLowerCase())).join(",");

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
		"The ledger is the truth, not your memory: use list_findings to see what is actually validated, and generate_report to produce a report — it is built ONLY from recorded Gate-1 facts and refuses anything unvalidated. NEVER hand-write a 'results'/'complete' file yourself; a free-text file you author is not an authoritative report and claiming completion you cannot show in the ledger is a serious integrity failure.",
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
		PLUTO_ENGAGEMENT_CLASS: domain,
		// Per-target state-DB isolation: each target gets its own pluto.db, so
		// targets never share one ledger (which accumulated stale-target rows).
		// Control files, logs, and evidence stay at the repo root — run one
		// engagement at a time (see state/db.ts stateDir docstring).
		PLUTO_STATE_DIR: `engagements/${label}/state`,
		// Per-engagement, pluto-WRITABLE log dir. Under --sandbox the repo root is
		// bind-mounted read-only, so a repo-root logs/ write fails silently and the
		// audit + disclosure trail is lost; the engagement dir is writable + bound
		// in, keeping "everything is logged" true in confined mode.
		PLUTO_LOG_DIR: `engagements/${label}/logs`,
		// Same read-only-under-sandbox rationale as PLUTO_LOG_DIR: keep Gate-1
		// evidence capture (validators, vision, exploit) writing to a pluto-writable
		// per-engagement dir instead of the read-only repo-root evidence/.
		PLUTO_EVIDENCE_DIR: `engagements/${label}/evidence`,
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
			maxCalls, maxWall, maxTokens, objective, tunnel, program, trafficId, rate, headless, sandbox, dryRun, domain,
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

const HELP = `Usage: cyberpluto <TARGET> [OBJECTIVE...] [options]

  TARGET is the first argument — an IP or hostname. There are NO subcommands.
    e.g.  pluto 192.168.122.68 "find and exploit web vulns, escalate to root"


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
  --domain NAME        Engagement class for launch provisioning (default web;
                       e.g. forensics, binary-exploitation, cryptography)
  --sandbox            Confine the agent: unprivileged 'pluto' uid, read-only
                       harness tree, nftables egress allowlist from scope (root;
                       run sandbox/setup.sh once first)
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

	const childEnv = { ...process.env, ...plan.env };

	// Structural, class-driven provisioning BEFORE handoff (Increment 3).
	provisionDomain(root, plan.domain);

	if (plan.sandbox) {
		if (process.getuid?.() !== 0) {
			process.stderr.write("cyberpluto --sandbox must be run as root (it applies the egress firewall and drops to the 'pluto' uid). Run sandbox/setup.sh first.\n");
			process.exitCode = 1; return;
		}
		// 1. Apply the authoritative egress allowlist from OPERATOR scope + the
		//    provider host(s), BEFORE the agent starts. pluto can't change it.
		const providerHosts = PROVIDER_HOSTS[plan.provider ?? "anthropic"] ?? [];
		const attackHosts = plan.attackProvider ? (PROVIDER_HOSTS[plan.attackProvider] ?? []) : [];
		// External-intel tool hosts (Shodan etc.): only allowed through egress when
		// the tool's key is present, so an unused intel tool widens nothing.
		const intelHosts = process.env.SHODAN_API_KEY ? (INTEL_HOSTS.shodan ?? []) : [];
		const egress = spawnSync(join(root, "sandbox/egress.sh"), ["apply", plan.scopeHosts.join(" "), ...providerHosts, ...attackHosts, ...intelHosts], { stdio: "inherit" });
		if (egress.status !== 0) { process.stderr.write("failed to apply egress allowlist; aborting.\n"); process.exitCode = 1; return; }
		// 2. Inject the provider credential into the child env (never on disk,
		//    never printed) — the confined `pluto` uid cannot read root's ~/.pi,
		//    so root extracts the key here and passes it as the provider env var.
		const keyEnv = PROVIDER_KEY_ENV[plan.provider ?? "anthropic"];
		if (keyEnv && !childEnv[keyEnv]) {
			const k = spawnSync("node", [PI_CLI, "auth", "print-api-key", "--provider", plan.provider ?? "anthropic"], { cwd: root, encoding: "utf8" });
			const key = (k.stdout ?? "").trim();
			if (k.status === 0 && key) childEnv[keyEnv] = key;
			else process.stderr.write(`warning: could not extract a ${plan.provider ?? "anthropic"} key to inject; the sandboxed agent may fail to authenticate.\n`);
		}
		// 3. Start the PRIVILEGED Gate-1 signing daemon as root, BEFORE dropping to
		//    pluto. It holds the promotion private key (which lives outside the
		//    pluto-readable tree) and listens on a socket in the pluto-writable
		//    engagement dir. The confined agent reaches it via the client — never
		//    sudo, which no_new_privs disables. If the key is absent the daemon is
		//    skipped and promotions are recorded UNSIGNED (consumer enforcement
		//    then treats them as untrusted); we warn loudly rather than fail.
		const engDir = join(root, "engagements", plan.label);
		mkdirSync(engDir, { recursive: true });
		const privKey = process.env.PLUTO_PROMOTION_PRIVKEY ?? PROMOTION_PRIVKEY_DEFAULT;
		const signSock = join(engDir, ".pluto-sign.sock");
		let signDaemon: ReturnType<typeof spawn> | undefined;
		if (existsSync(privKey)) {
			// The daemon needs the key + the SAME state-dir view as the agent, but
			// the child (pluto) env must NOT carry the private key.
			const daemonEnv = { ...process.env, ...plan.env, PLUTO_PROMOTION_PRIVKEY: privKey, PLUTO_CWD: root };
			signDaemon = spawn("node", [join(root, PROMOTION_DAEMON_JS), signSock], {
				cwd: root, stdio: ["ignore", "ignore", "inherit"], env: daemonEnv,
			});
			if (!waitForPathSync(signSock)) {
				process.stderr.write("promotion signing daemon did not come up; aborting (would run without Gate-1 signing).\n");
				signDaemon.kill("SIGTERM");
				spawnSync(join(root, "sandbox/egress.sh"), ["teardown"], { stdio: "ignore" });
				process.exitCode = 1; return;
			}
			// Point the confined agent at the client (reached via the sync CMD
			// signer). The key never enters the child env.
			childEnv.PLUTO_PROMOTION_SIGNER_CMD = `${process.execPath} ${join(root, PROMOTION_CLIENT_JS)} ${signSock}`;
			// Turn on consumer enforcement in the child: the PUBLIC key (world-read)
			// lets it distrust an unsigned/invalid 'validated' finding at Gate-2.
			const pubKey = privKey.replace(/\.key$/, ".pub");
			if (existsSync(pubKey)) childEnv.PLUTO_PROMOTION_PUBKEY = pubKey;
		} else {
			process.stderr.write(
				`warning: promotion private key ${privKey} not found — running WITHOUT Gate-1 signing (promotions will be unsigned/untrusted). Run sandbox/setup.sh to generate it.\n`,
			);
		}
		// 4. Run the agent confined (setpriv no_new_privs + bwrap + owner-match).
		const child = spawn(join(root, "sandbox/run-sandboxed.sh"), [engDir, "--", "node", ...plan.cliArgs], {
			cwd: root, stdio: "inherit", env: childEnv,
		});
		child.on("exit", (code) => {
			signDaemon?.kill("SIGTERM");
			spawnSync(join(root, "sandbox/egress.sh"), ["teardown"], { stdio: "ignore" });
			process.exitCode = code ?? 0;
		});
		return;
	}

	const child = spawn("node", plan.cliArgs, { cwd: root, stdio: "inherit", env: childEnv });
	child.on("exit", (code) => { process.exitCode = code ?? 0; });
}

/** Provider → the API host(s) to allow through the egress firewall (resolved +
 * pinned at launch by egress.sh). The scope target is added separately. */
/** Provider → the env var Pi reads its key from, so the root launcher can inject
 * the stored credential into the confined child (which can't read root's ~/.pi). */
const PROVIDER_KEY_ENV: Record<string, string> = {
	anthropic: "ANTHROPIC_API_KEY",
	openai: "OPENAI_API_KEY",
	deepseek: "DEEPSEEK_API_KEY",
	zai: "ZAI_API_KEY",
	groq: "GROQ_API_KEY",
};

/** External-intel tool → the third-party API host(s) added to the egress
 * allowlist by the root launcher when that tool's key is configured (Decision
 * 0001: thin per-vendor REST extensions, egress-gated). */
const INTEL_HOSTS: Record<string, string[]> = {
	shodan: ["api.shodan.io"],
};

const PROVIDER_HOSTS: Record<string, string[]> = {
	anthropic: ["api.anthropic.com"],
	openai: ["api.openai.com"],
	"openai-codex": ["chatgpt.com", "api.openai.com"],
	deepseek: ["api.deepseek.com"],
	zai: ["api.z.ai", "open.bigmodel.cn"],
	groq: ["api.groq.com"],
};

// Only run main when invoked directly (not when imported by tests).
if (process.argv[1] && process.argv[1].endsWith("launcher/index.js")) {
	void main();
}
