/**
 * msf-bridge: the thin TS→Python edge for the Metasploit bridge (same IPC
 * pattern as kb-bridge). All exploitation MECHANISM lives in Python
 * (`services/pluto_services/msf_bridge`); this only shells out and parses JSON.
 * The gates live in the exploit extension that calls this, never here.
 */
import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const TIMEOUT_MS = 60000;

export interface ExploitTargetInput {
	host: string;
	port?: number | null;
	service?: string | null;
	product?: string | null;
	version?: string | null;
	mechanism?: string | null;
}

export interface ModuleMatch {
	fullname: string;
	name: string;
	rank: string;
	fit: number;
}

export interface CustomPayloadSpec {
	payload_type: string;
	lhost: string;
	lport: number;
	transport: string;
	encoder: string | null;
	generated_code: string;
}

export interface ExploitPlan {
	mode: "metasploit_module" | "custom_payload";
	target: ExploitTargetInput;
	rationale: string;
	module: ModuleMatch | null;
	payload: CustomPayloadSpec | null;
}

export interface ExploitResult {
	ok: boolean;
	mode: string;
	module: string | null;
	session_opened: boolean;
	session_id: number | null;
	output: string;
}

function targetArgs(t: ExploitTargetInput): string[] {
	const args = ["--host", t.host];
	if (t.port) args.push("--port", String(t.port));
	if (t.service) args.push("--service", t.service);
	if (t.product) args.push("--product", t.product);
	if (t.version) args.push("--version", t.version);
	if (t.mechanism) args.push("--mechanism", t.mechanism);
	return args;
}

async function runCli(cwd: string, args: string[]): Promise<unknown> {
	const python = join(cwd, "services", ".venv", "bin", "python");
	const { stdout } = await execFileAsync(python, ["-m", "pluto_services.msf_bridge.cli", ...args], {
		cwd,
		env: { ...process.env, PYTHONPATH: join(cwd, "services") },
		timeout: TIMEOUT_MS,
		maxBuffer: 4 * 1024 * 1024,
	});
	return JSON.parse(stdout.trim());
}

export async function planExploit(
	cwd: string,
	target: ExploitTargetInput,
	opts: { lhost?: string; lport?: number } = {},
): Promise<ExploitPlan> {
	const args = ["plan", ...targetArgs(target), "--lhost", opts.lhost ?? "127.0.0.1", "--lport", String(opts.lport ?? 4444)];
	return (await runCli(cwd, args)) as ExploitPlan;
}

export async function runModule(
	cwd: string,
	target: ExploitTargetInput,
	moduleFullname: string,
	payload: string,
): Promise<ExploitResult> {
	const args = ["run", ...targetArgs(target), "--module", moduleFullname, "--payload", payload];
	return (await runCli(cwd, args)) as ExploitResult;
}
