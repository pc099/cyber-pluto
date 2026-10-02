/** Readiness validation has no launch, provisioning, migration or model effects. */
import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { bindingPath, canonicalPath, configuredAssociation, readBinding, type SessionBinding } from "../state/session-binding.js";
import { getProviderHold, readOutcome } from "../lifecycle/provider-outcome.js";

export const SANDBOX_RUNTIME = "/opt/cyber-pluto";
export const SANDBOX_ENGAGEMENTS = "/var/lib/cyber-pluto/engagements";
export const SANDBOX_CONTROL = "/var/lib/cyber-pluto/control";
export const SANDBOX_RUN = "/run/cyber-pluto";

/** A writable workspace is not an authority boundary. Its root must nevertheless
 * be directly beneath the protected engagement directory, never an alias. */
export function assertNoSymlinkAncestors(path: string): void {
	let current = resolve(path);
	while (true) {
		if (existsSync(current)) {
			if (lstatSync(current).isSymbolicLink()) throw new Error(`Sandbox refuses symlink path: ${current}`);
		} else {
			// existsSync follows links; inspect dangling links as well.
			try { if (lstatSync(current).isSymbolicLink()) throw new Error(`Sandbox refuses symlink path: ${current}`); }
			catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
		}
		const parent = dirname(current);
		if (parent === current) break;
		current = parent;
	}
}

export function assertProtectedDirectory(path: string, requireTraversal = false): void {
	assertNoSymlinkAncestors(path);
	const info = lstatSync(path);
	if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022)) throw new Error(`Sandbox directory must be root-owned and not group/world writable: ${path}`);
	if (requireTraversal && (info.mode & 0o055) !== 0o055) throw new Error(`Sandbox directory is not publicly traversable: ${path}`);
}

/** Reject private mount roots even where the wrapper exposes a subtree;
 * verifier keys use an ordinary visible host path such as /etc/cyber-pluto. */
export function assertSandboxVerifierPath(publicPath: string): void {
	const path = resolve(publicPath);
	for (const hidden of ["/root", "/tmp", "/run"]) {
		if (path === hidden || path.startsWith(`${hidden}/`)) throw new Error("Promotion public key is hidden by the sandbox mount namespace");
	}
}

export function verifyKeypair(privatePath: string, publicPath: string): void {
	for (const path of [privatePath, publicPath]) {
		assertNoSymlinkAncestors(path);
		const info = lstatSync(path);
		if (!info.isFile() || info.uid !== 0 || (info.mode & 0o022)) throw new Error(`Unsafe promotion key ownership/mode: ${path}`);
		for (let parent = dirname(path); ; parent = dirname(parent)) {
			assertProtectedDirectory(parent);
			if (path === publicPath && !(lstatSync(parent).mode & 0o001)) throw new Error("Promotion public key parents must be traversable by the sandbox uid");
			if (dirname(parent) === parent) break;
		}
	}
	if (lstatSync(privatePath).mode & 0o077) throw new Error("Promotion private key must be root-only");
	if (!(lstatSync(publicPath).mode & 0o004)) throw new Error("Promotion public key must be world-readable by the sandbox uid");
	const privateKey = createPrivateKey(readFileSync(privatePath));
	const publicKey = createPublicKey(readFileSync(publicPath));
	if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519") throw new Error("Promotion keys must be Ed25519");
	const challenge = randomBytes(32);
	if (!verify(null, challenge, publicKey, sign(null, challenge, privateKey))) throw new Error("Promotion signing/verifying keypair mismatch");
}

interface TranscriptEntry { type: string; id?: string; parentId?: string | null; customType?: string; data?: unknown; version?: number }
/** Mirror Pi's current-session last-leaf parent traversal without SessionManager
 * opening/re-writing legacy files during preflight. Unsupported formats fail. */
export function selectedBindingMetadata(sessionFile: string): { sessionId: string; metadata?: SessionBinding } {
	const records = readFileSync(sessionFile, "utf8").split("\n").filter(line => line.trim()).map(line => JSON.parse(line) as TranscriptEntry);
	const header = records[0];
	if (header?.type !== "session" || header.version !== 3 || typeof header.id !== "string") throw new Error("Sandbox resume requires an existing Pi v3 transcript; format migration is separate");
	const byId = new Map<string, TranscriptEntry>();
	let leaf: TranscriptEntry | undefined;
	for (const entry of records.slice(1)) {
		if (!entry || typeof entry.id !== "string" || byId.has(entry.id)) throw new Error("Invalid or duplicate Pi transcript entry");
		byId.set(entry.id, entry); leaf = entry;
	}
	const visited = new Set<string>();
	let metadata: SessionBinding | undefined;
	while (leaf) {
		if (!leaf.id || visited.has(leaf.id)) throw new Error("Invalid cyclic Pi selected branch");
		visited.add(leaf.id);
		if (!metadata && leaf.type === "custom" && leaf.customType === "pluto-engagement-binding") metadata = leaf.data as SessionBinding;
		const parent = leaf.parentId;
		if (parent === null || parent === undefined) break;
		leaf = byId.get(parent);
		if (!leaf) throw new Error("Missing parent on Pi selected branch");
	}
	return { sessionId: header.id, metadata };
}

export function preflightSandboxSession(sessionFile: string, runtime: string, env: NodeJS.ProcessEnv, sessionsDirectory: string, options: { allowHeldDiagnostics?: boolean } = {}): SessionBinding {
	assertNoSymlinkAncestors(sessionFile);
	const file = canonicalPath(sessionFile);
	if (!file.startsWith(`${canonicalPath(sessionsDirectory)}${sep}`)) throw new Error("Bound-v1 session relocation/conversion is unsupported; preserve source and use a fresh confined session");
	const binding = readBinding(bindingPath(file));
	const association = configuredAssociation(runtime, env);
	if (JSON.stringify(binding.association) !== JSON.stringify(association)) throw new Error("Bound-v1 session association differs; sandbox conversion/relocation is unsupported");
	const selected = selectedBindingMetadata(file);
	if (selected.sessionId !== binding.sessionId || !selected.metadata || JSON.stringify(selected.metadata.association) !== JSON.stringify(binding.association)) throw new Error("Selected Pi branch conflicts with its durable engagement descriptor");
	if (selected.metadata.sessionId !== binding.sessionId || selected.metadata.sessionFile !== binding.sessionFile) throw new Error("Selected Pi branch session identity conflicts with descriptor");
	const hold = getProviderHold(binding);
	if (hold.blocked && !options.allowHeldDiagnostics) throw new Error(`Sandbox resume held: ${hold.reason}; readiness cannot reset a saved hold`);
	if (!readOutcome(binding) && binding.forkedFrom) {
		const parent = readBinding(bindingPath(binding.forkedFrom.sessionFile));
		if (parent.sessionId !== binding.forkedFrom.sessionId || JSON.stringify(parent.association) !== JSON.stringify(binding.association)) throw new Error("Fork interruption provenance conflicts with saved association");
		const inherited = getProviderHold(parent);
		if (inherited.blocked && !options.allowHeldDiagnostics) throw new Error(`Sandbox fork inherits hold: ${inherited.reason}; readiness cannot reset parent history`);
	}
	return binding;
}

/** A paused saved run may reopen its operator console without granting any
 * provider/tool work. Only a matching selected session can reach /unpause. */
export function assertWorkspaceControls(engagement: string, options: { selectedBinding?: SessionBinding; headless: boolean; sandboxCheck: boolean }): void {
	if (existsSync(join(engagement, "state", "KILL_SWITCH"))) throw new Error("Saved workspace control hold active: KILL_SWITCH");
	if (!existsSync(join(engagement, "state", "PAUSED"))) return;
	const interactiveResume = !options.headless && !options.sandboxCheck &&
		options.selectedBinding?.association.stateDir === canonicalPath(join(engagement, "state"));
	if (!interactiveResume) throw new Error("Saved workspace control hold active: PAUSED");
}

export function sandboxEnvironment(base: NodeJS.ProcessEnv, dynamics: Record<string, string>, runtime: string, engagement: string, signerDirectory: string, publicKey: string): NodeJS.ProcessEnv {
	const env = { ...base, ...dynamics };
	// Do not inherit path/identity/security-control overrides from another run.
	for (const key of Object.keys(env)) if (key.startsWith("PLUTO_") && !(key in dynamics)) delete env[key];
	Object.assign(env, {
		PLUTO_LAUNCHER: "1", PLUTO_SANDBOX_MODE: "requested", PLUTO_BWRAP: "1", PLUTO_CWD: runtime,
		PLUTO_STATE_DIR: join(engagement, "state"), PLUTO_LOG_DIR: join(engagement, "logs"), PLUTO_EVIDENCE_DIR: join(engagement, "evidence"),
		PLUTO_CONTROL_DIR: SANDBOX_CONTROL, PLUTO_KILL_FILE: join(SANDBOX_CONTROL, "KILL_SWITCH"), PLUTO_RUN_DIR: SANDBOX_RUN,
		PLUTO_SIGNER_DIR: signerDirectory, PLUTO_PROMOTION_PUBKEY: publicKey,
		PLUTO_PROMOTION_SIGNER_SOCK: join(signerDirectory, "promotion.sock"),
		PLUTO_PROMOTION_SIGNER_CMD: `${process.execPath} ${join(runtime, "extensions/dist/state/promotion-sign-client.js")} ${join(signerDirectory, "promotion.sock")}`,
		PI_CODING_AGENT_DIR: join(engagement, "pi-agent"), PLUTO_UID: "pluto",
	});
	delete env.PLUTO_PROMOTION_PRIVKEY;
	delete env.PLUTO_ADOPT_SESSION;
	return env;
}
