/** Root launch transaction. This module never deploys runtime files or migrates
 * saved sessions. The readiness branch launches only a local fixture probe. */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { chownSync, chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmdirSync, rmSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { SCHEMA_SQL } from "../state/schema.js";
import { checkSignerHealth } from "../state/signer-health.js";
import { injectCodexAccessToken } from "../sandbox-auth/credentials.js";
import { validateRuntime } from "./deploy.js";
import { canonicalPath } from "../state/session-binding.js";
import { assertNoSymlinkAncestors, assertProtectedDirectory, assertSandboxVerifierPath, assertWorkspaceControls, preflightSandboxSession, sandboxEnvironment, verifyKeypair, SANDBOX_CONTROL, SANDBOX_ENGAGEMENTS, SANDBOX_RUN, SANDBOX_RUNTIME } from "./sandbox-preflight.js";
import { findCapability } from "../capabilities/manifest.js";
import { getProviderHold } from "../lifecycle/provider-outcome.js";
import type { LaunchPlan } from "./index.js";

const sleep = (milliseconds: number): Promise<void> => new Promise(resolve => setTimeout(resolve, milliseconds));
const PRIVATE_KEY = "/etc/cyber-pluto/promotion_ed25519.key";
const API_KEYS: Record<string, string> = { anthropic: "ANTHROPIC_API_KEY", openai: "OPENAI_API_KEY", deepseek: "DEEPSEEK_API_KEY", zai: "ZAI_API_KEY", groq: "GROQ_API_KEY" };

/** No stale-lock auto-recovery: root must inspect quiescence and resources first. */
export function acquireLaunchLock(runDirectory: string, runId: string): () => void {
	assertProtectedDirectory(runDirectory);
	const path = join(runDirectory, "launch.lock");
	mkdirSync(path, { mode: 0o700 }); // exclusive; EEXIST never alters another launch
	const identity = lstatSync(path);
	try { writeFileSync(join(path, "owner.json"), JSON.stringify({ runId, pid: process.pid, createdAt: new Date().toISOString() }), { flag: "wx", mode: 0o600 }); }
	catch (error) { rmdirSync(path); throw error; }
	return () => {
		const current = lstatSync(path);
		if (current.dev !== identity.dev || current.ino !== identity.ino) throw new Error("Launch lock identity changed; refusing cleanup");
		rmSync(join(path, "owner.json"));
		rmdirSync(path);
	};
}

export interface Quiescence { known: boolean; pids: number[] }
/** Inspect all real/effective/saved/fs UIDs; no permission failure means quiet. */
export function uidQuiescence(uid: number, procRoot = "/proc"): Quiescence {
	const pids: number[] = [];
	try {
		for (const directory of readdirSync(procRoot)) {
			if (!/^\d+$/.test(directory)) continue;
			try {
				const text = readFileSync(join(procRoot, directory, "status"), "utf8");
				const ids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m.exec(text);
				if (!ids) return { known: false, pids };
				if (ids.slice(1).some(value => Number(value) === uid)) pids.push(Number(directory));
			} catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT" && (error as NodeJS.ErrnoException).code !== "ESRCH") return { known: false, pids }; }
		}
		return { known: true, pids };
	} catch { return { known: false, pids }; }
}

export interface CleanupOperations {
	stopChild(): Promise<boolean>;
	stopSigner(): Promise<boolean>;
	quiescence(): Quiescence;
	teardownEgress(): boolean;
	recovery(reason: string): void;
	release(): void;
}
/** A direct-child exit never establishes that detached UID workloads stopped. */
export async function cleanupSandbox(ops: CleanupOperations, egressAcquired: boolean, arbitraryDispatch = false): Promise<boolean> {
	const childStopped = await ops.stopChild();
	const signerStopped = await ops.stopSigner();
	if (arbitraryDispatch) {
		ops.recovery("Production workload dispatched; descendant termination requires explicit root recovery; owned policy and launch lock retained");
		return false;
	}
	const quiet = ops.quiescence();
	if (!childStopped || !signerStopped || !quiet.known || quiet.pids.length) {
		ops.recovery(`Workloads/signing termination unconfirmed; confinedPids=${quiet.pids.join(",")}; restrictive policy retained`);
		return false;
	}
	if (egressAcquired && !ops.teardownEgress()) {
		ops.recovery("Egress teardown failed; policy/lock retained for explicit root recovery");
		return false;
	}
	try { ops.release(); }
	catch (error) { ops.recovery(`Resource release failed: ${String(error)}; lock retained for explicit root recovery`); return false; }
	return true;
}

/** Check cancellation on both sides of awaited readiness; a health response
 * cannot resurrect startup after a termination signal. */
export async function waitForSandboxReadiness(check: () => Promise<unknown>, interrupted: () => boolean, timeoutMs = 5000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (true) {
		if (interrupted()) throw new Error("Signing startup interrupted");
		try {
			await check();
			if (interrupted()) throw new Error("Signing startup interrupted after readiness");
			return;
		} catch (error) {
			if (interrupted()) throw new Error("Signing startup interrupted");
			if (Date.now() >= deadline) throw new Error(`Signer readiness failed: ${String(error)}`);
			await sleep(50);
		}
	}
}

/** The owned process remains available to transaction cleanup on timeout. */
export async function waitForLedgerProbe(completion: Promise<number>, timeoutMs = 5000): Promise<void> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const code = await Promise.race([completion, new Promise<number>((_resolve, reject) => {
			timer = setTimeout(() => reject(new Error("Confined ledger readiness timed out")), timeoutMs);
		})]);
		if (code !== 0) throw new Error("Confined ledger readiness failed");
	} finally { if (timer) clearTimeout(timer); }
}

function command(program: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; quiet?: boolean } = {}): void {
	const result = spawnSync(program, args, { cwd: options.cwd, env: options.env, stdio: options.quiet ? "ignore" : "inherit", timeout: 15_000 });
	if (result.error || result.status !== 0) throw new Error(`Sandbox command failed: ${program} (${result.error?.message ?? result.signal ?? result.status})`);
}

/** Handle spawn errors immediately even while readiness is waiting. */
function start(program: string, args: string[], env: NodeJS.ProcessEnv, runtime: string): { child: ChildProcess; completion: Promise<number>; fault: () => Error | undefined } {
	const child = spawn(program, args, { cwd: runtime, env, stdio: "inherit", detached: true });
	let error: Error | undefined;
	const completion = new Promise<number>(resolve => {
		child.once("error", problem => { error = problem; resolve(1); });
		child.once("exit", (code, signal) => resolve(code ?? (signal ? 128 : 1)));
	});
	return { child, completion, fault: () => error };
}

async function stop(processHandle: ReturnType<typeof start> | undefined): Promise<boolean> {
	if (!processHandle) return true;
	const { child } = processHandle;
	if (processHandle.fault() && !child.pid) return true;
	// The daemon may exit before its persistent reader. Signal its owned group
	// even when the direct child has already settled.
	try { if (child.pid) process.kill(-child.pid, "SIGTERM"); }
	catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") return false; }
	if (await Promise.race([processHandle.completion.then(() => true), sleep(2000).then(() => false)])) return true;
	try { if (child.pid) process.kill(-child.pid, "SIGKILL"); }
	catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") return false; }
	return Promise.race([processHandle.completion.then(() => true), sleep(2000).then(() => false)]);
}

function workspace(path: string, uid: number, gid: number): void {
	assertNoSymlinkAncestors(path);
	if (!existsSync(path)) { mkdirSync(path, { mode: 0o750 }); chownSync(path, uid, gid); }
	for (const name of ["", "state", "logs", "evidence", "sessions", "pi-agent"]) {
		const directory = join(path, name);
		if (!existsSync(directory)) { mkdirSync(directory, { mode: 0o750 }); chownSync(directory, uid, gid); }
		assertNoSymlinkAncestors(directory);
		const info = lstatSync(directory);
		if (!info.isDirectory() || info.uid !== uid || (info.mode & 0o007)) throw new Error(`Unsafe sandbox workspace: ${directory}`);
	}
	const ledger = join(path, "state/pluto.db");
	assertNoSymlinkAncestors(ledger);
	if (!existsSync(ledger)) {
		const database = new DatabaseSync(ledger);
		try { database.exec(SCHEMA_SQL); } finally { database.close(); }
		chownSync(ledger, uid, gid); chmodSync(ledger, 0o600);
	}
	if (!lstatSync(ledger).isFile() || lstatSync(ledger).uid !== uid || (lstatSync(ledger).mode & 0o007)) throw new Error("Unsafe sandbox ledger ownership/mode");
}

function assertFixedParents(): void {
	for (const path of ["/opt", "/var", "/var/lib", "/var/lib/cyber-pluto", SANDBOX_ENGAGEMENTS, SANDBOX_CONTROL, "/run", SANDBOX_RUN]) assertProtectedDirectory(path, true);
	for (const control of ["KILL_SWITCH", "PAUSED", "RECOVERY_REQUIRED.json"]) if (existsSync(join(SANDBOX_CONTROL, control))) throw new Error(`Sandbox control hold active: ${control}`);
}

function sandboxCapabilities(runtime: string): void {
	if (process.env.PLUTO_BWRAP === "0") throw new Error("Requested sandbox cannot run with PLUTO_BWRAP=0");
	command("setpriv", ["--no-new-privs", "--reuid", "pluto", "--regid", "pluto", "--init-groups", "--", "bwrap", "--ro-bind", "/", "/", "--tmpfs", "/root", "--tmpfs", "/tmp", "--dev", "/dev", "--proc", "/proc", "--chdir", runtime, "/usr/bin/true"], { quiet: true, env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/nonexistent" } });
}

export async function runSandbox(plan: LaunchPlan, selectedSession: string | undefined, providerHosts: string[]): Promise<number> {
	if (process.getuid?.() !== 0) throw new Error("Sandbox launch/readiness requires root");
	if (plan.adoptSession) throw new Error("Sandbox adoption/conversion of historical sessions is unsupported; preserve source");
	const runtime = SANDBOX_RUNTIME;
	const privateSetting = process.env.PLUTO_PROMOTION_PRIVKEY ?? PRIVATE_KEY;
	const publicSetting = process.env.PLUTO_PROMOTION_PUBKEY ?? privateSetting.replace(/\.key$/, ".pub");
	if (privateSetting === publicSetting) throw new Error("Signing private/public paths must be distinct; configure PLUTO_PROMOTION_PUBKEY");
	assertNoSymlinkAncestors(privateSetting); assertNoSymlinkAncestors(publicSetting);
	const privateKey = canonicalPath(privateSetting);
	const publicKey = canonicalPath(publicSetting);
	const engagement = join(SANDBOX_ENGAGEMENTS, plan.label);
	const sessions = join(engagement, "sessions");
	const signerDirectory = join(SANDBOX_RUN, "signers", plan.label);
	assertNoSymlinkAncestors(engagement);
	const env = sandboxEnvironment(process.env, plan.env, runtime, engagement, signerDirectory, publicKey);
	// Session refusal occurs before creating destination directories or launching
	// a capability probe. This never writes descriptors or consumes recovery.
	const selectedBinding = selectedSession ? preflightSandboxSession(selectedSession, runtime, env, sessions, { allowHeldDiagnostics: plan.sandboxCheck || !plan.headless }) : undefined;
	if (selectedBinding) {
		const hold = getProviderHold(selectedBinding);
		if (hold.blocked) process.stderr.write(`Saved session hold remains active (${hold.reason}); diagnostic startup cannot clear it or retry provider work.\n`);
	}
	assertWorkspaceControls(engagement, { selectedBinding, headless: plan.headless, sandboxCheck: plan.sandboxCheck });
	assertFixedParents();
	validateRuntime(runtime);
	assertNoSymlinkAncestors(process.execPath);
	const node = lstatSync(process.execPath);
	if (process.execPath.startsWith("/root/") || !node.isFile() || node.uid !== 0 || (node.mode & 0o022) || (node.mode & 0o055) !== 0o055) throw new Error("Sandbox Node executable must be protected and accessible outside /root");
	assertSandboxVerifierPath(publicKey);
	verifyKeypair(privateKey, publicKey);
	sandboxCapabilities(runtime);
	const uid = Number(spawnSync("id", ["-u", "pluto"], { encoding: "utf8" }).stdout?.trim());
	const gid = Number(spawnSync("id", ["-g", "pluto"], { encoding: "utf8" }).stdout?.trim());
	if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0) throw new Error("Dedicated pluto identity unavailable");
	if (!plan.sandboxCheck) {
		const capability = findCapability(plan.domain);
		if (!capability) throw new Error(`Unknown sandbox capability: ${plan.domain}`);
		command("bash", ["-c", capability.verify], { cwd: runtime, quiet: true }); // verify only; no installation
		for (const provider of new Set([plan.provider ?? "openai-codex", ...(plan.attackProvider ? [plan.attackProvider] : [])])) {
			if (provider === "openai-codex") {
				if (plan.maxWall === 0) throw new Error("Sandbox OAuth access injection requires a finite wall-clock cap");
				injectCodexAccessToken(env, join(homedir(), ".pi/agent/auth.json"), Date.now(), plan.maxWall * 1000 + 300_000);
			} else {
				const key = API_KEYS[provider];
				if (!key || !env[key]?.trim()) throw new Error(`Sandbox provider requires a configured environment credential: ${provider}`);
			}
		}
	}
	const runId = randomUUID();
	const policyEnv = { ...process.env, PLUTO_UID: "pluto", PLUTO_EGRESS_RUN_ID: runId, LC_ALL: "C" };
	let release: (() => void) | undefined;
	let daemon: ReturnType<typeof start> | undefined;
	let child: ReturnType<typeof start> | undefined;
	let egressAcquired = false;
	let arbitraryDispatch = false;
	let scratch: string | undefined;
	let signalReceived = false;
	let cleanupPromise: Promise<boolean> | undefined;
	const recover = (reason: string): void => {
		writeFileSync(join(SANDBOX_CONTROL, "RECOVERY_REQUIRED.json"), `${JSON.stringify({ schema: 1, runId, reason, time: new Date().toISOString() })}\n`, { flag: "wx", mode: 0o600 });
		process.stderr.write(`Sandbox recovery required: ${reason}\n`);
	};
	const cleanup = (): Promise<boolean> => {
		if (!cleanupPromise) cleanupPromise = cleanupSandbox({
			stopChild: () => stop(child), stopSigner: () => stop(daemon), quiescence: () => uidQuiescence(uid),
			teardownEgress: () => spawnSync(join(runtime, "sandbox/egress.sh"), ["teardown"], { env: policyEnv, stdio: "inherit", timeout: 5000 }).status === 0,
			recovery: recover, release: () => {
				if (scratch) rmSync(scratch, { recursive: true });
				release?.(); release = undefined;
			},
		}, egressAcquired, arbitraryDispatch);
		return cleanupPromise;
	};
	// Signals cancel startup; only the main transaction performs cleanup. Never
	// release the lock/policy concurrently with an awaited readiness operation.
	const signal = (): void => {
		signalReceived = true;
		for (const handle of [child, daemon]) {
			try { if (handle?.child.pid) process.kill(-handle.child.pid, "SIGTERM"); }
			catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") process.stderr.write(`Sandbox signal delivery failed: ${String(error)}\n`); }
		}
	};
	try {
		release = acquireLaunchLock(SANDBOX_RUN, runId);
		process.on("SIGINT", signal); process.on("SIGTERM", signal);
		const quiet = uidQuiescence(uid);
		if (!quiet.known || quiet.pids.length) { recover("Existing/unknown confined UID workloads; launch refused and lock retained"); release = undefined; throw new Error("Confined UID is not quiescent; root recovery required"); }
		// An unrelated table is never deleted by egress apply. A retained old table
		// requires explicit recovery even if the launch lock was manually removed.
		const table = spawnSync("nft", ["-j", "list", "tables"], { encoding: "utf8", timeout: 5000 });
		if (table.error || table.status !== 0) throw new Error("Cannot inspect existing egress protection");
		const tables = JSON.parse(table.stdout) as { nftables?: Array<{ table?: { family?: string; name?: string } }> };
		if (!Array.isArray(tables.nftables)) throw new Error("Invalid nftables inventory");
		if (tables.nftables.some(entry => entry.table?.family === "inet" && entry.table.name === "pluto_egress")) { recover("Existing egress table; launch refused without replacing protection"); release = undefined; throw new Error("Existing egress protection requires root recovery"); }
		let activeEngagement = engagement;
		if (plan.sandboxCheck) {
			scratch = join(SANDBOX_ENGAGEMENTS, `readiness-${runId}`);
			activeEngagement = scratch;
		}
		workspace(activeEngagement, uid, gid);
		const childEnv = plan.sandboxCheck ? sandboxEnvironment(process.env, plan.env, runtime, activeEngagement, signerDirectory, publicKey) : env;
		childEnv.PLUTO_SIGNER_RUN_ID = runId;
		childEnv.PLUTO_READINESS_UID = String(uid);
		childEnv.PLUTO_READINESS_ONLY = plan.sandboxCheck ? "1" : "0";
		if (plan.sandboxCheck) childEnv.PLUTO_READINESS_KEY_DENY_PATH = privateKey;
		for (const path of [join(SANDBOX_RUN, "signers"), signerDirectory]) {
			if (!existsSync(path)) mkdirSync(path, { mode: 0o755 });
			assertProtectedDirectory(path, true);
		}
		const socketPath = join(signerDirectory, "promotion.sock");
		if (existsSync(socketPath)) throw new Error("Existing signer endpoint requires explicit root recovery");
		// From this point, a failed apply may have created a partial policy; cleanup
		// owns its removal only after confirming workloads are absent.
		egressAcquired = true;
		command(join(runtime, "sandbox/egress.sh"), ["apply", plan.sandboxCheck ? "127.0.0.1" : plan.scopeHosts.join(" "), ...(plan.sandboxCheck ? [] : providerHosts)], { env: policyEnv });
		// A cold WAL reader may create SQLite metadata even with readOnly=true.
		// Prepare it as the confined UID; root never chowns agent sidecars.
		if (signalReceived) throw new Error("Launch interrupted before ledger readiness");
		child = start(join(runtime, "sandbox/run-sandboxed.sh"), [activeEngagement, "--", process.execPath, join(runtime, "extensions/dist/launcher/ledger-probe.js")], childEnv, runtime);
		await waitForLedgerProbe(child.completion);
		if (signalReceived) throw new Error("Launch interrupted before signer startup");
		daemon = start(process.execPath, [join(runtime, "extensions/dist/state/promotion-sign-daemon.js"), socketPath], { ...childEnv, PLUTO_PROMOTION_PRIVKEY: privateKey, PLUTO_SIGNER_STRICT: "1", PLUTO_SIGNER_RUN_ID: runId }, runtime);
		const healthOptions = { socketPath, ledgerPath: join(childEnv.PLUTO_STATE_DIR!, "pluto.db"), runId, publicKeyPath: publicKey, timeoutMs: 500 };
		await waitForSandboxReadiness(() => checkSignerHealth(healthOptions), () => Boolean(signalReceived || daemon?.fault() || daemon?.child.exitCode !== null || daemon?.child.signalCode !== null));
		if (signalReceived) throw new Error("Launch interrupted after signer readiness");
		const args = [...plan.cliArgs];
		args[0] = join(runtime, args[0]!);
		args[args.indexOf("--session-dir") + 1] = sessions;
		if (selectedSession) args[args.indexOf("--session") + 1] = selectedSession;
		const payload = plan.sandboxCheck ? [process.execPath, join(runtime, "extensions/dist/launcher/sandbox-probe.js")] : [process.execPath, ...args];
		// Monotonic before the spawn attempt: an ambiguous failure cannot authorize
		// production policy release. Supervised teardown remains separate work.
		if (!plan.sandboxCheck) arbitraryDispatch = true;
		child = start(join(runtime, "sandbox/run-sandboxed.sh"), [activeEngagement, "--", ...payload], childEnv, runtime);
		const result = await child.completion;
		if (!(await cleanup())) return 1;
		return signalReceived ? 130 : result;
	} catch (error) {
		// Never clean resources without the lock this launch acquired.
		if (release) await cleanup();
		throw error;
	} finally {
		process.off("SIGINT", signal); process.off("SIGTERM", signal);
	}
}
