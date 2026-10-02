/** Accidental-rebinding guard. Agent-readable metadata is not scope authority. */
import { randomUUID, createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, mkdirSync, openSync, writeFileSync, fsyncSync, closeSync, linkSync, unlinkSync } from "node:fs";
import { dirname, basename, resolve, join } from "node:path";
import { getProviderHold } from "../lifecycle/provider-outcome.js";
import { killSwitchPath } from "../red-lines/kill-switch.js";

export interface EngagementAssociation {
	label: string;
	host: string;
	stateDir: string;
	logDir: string;
	evidenceDir: string;
	scope: string[];
	signingMode: string;
	signingReference: string;
	sandboxMode: string;
}
export interface SessionBinding {
	schema: 1;
	sessionId: string;
	sessionFile: string;
	association: EngagementAssociation;
	origin: "new" | "adopted" | "fork";
	createdAt: string;
	forkedFrom?: { sessionId: string; sessionFile: string; outcomePath: string };
}
export class SessionBindingError extends Error {
	constructor(message: string) { super(`Engagement binding blocked: ${message}`); this.name = "SessionBindingError"; }
}

/** Resolve symlinks through the nearest existing parent, including unborn paths. */
export function canonicalPath(path: string, cwd = process.cwd()): string {
	const absolute = resolve(cwd, path);
	if (existsSync(absolute)) return realpathSync(absolute);
	const parent = dirname(absolute);
	return parent === absolute ? absolute : join(canonicalPath(parent), basename(absolute));
}
function required(env: NodeJS.ProcessEnv, key: string): string {
	const value = env[key]?.trim();
	if (!value) throw new SessionBindingError(`missing ${key}; launch with pluto --target --label --scope (resume with --session).`);
	return value;
}
export function configuredAssociation(cwd: string, env: NodeJS.ProcessEnv = process.env): EngagementAssociation {
	const label = required(env, "PLUTO_TARGET_LABEL");
	const host = required(env, "PLUTO_TARGET_HOST").toLowerCase();
	const scope = [...new Set(required(env, "PLUTO_SCOPE_HOSTS").split(/[,\s]+/).filter(Boolean).map(x => x.toLowerCase()))].sort();
	if (!scope.includes(host)) throw new SessionBindingError("primary target is absent from explicit scope");
	const signer = env.PLUTO_PROMOTION_SIGNER_CMD?.trim();
	const key = env.PLUTO_PROMOTION_PRIVKEY?.trim();
	return {
		label, host, scope,
		stateDir: canonicalPath(required(env, "PLUTO_STATE_DIR"), cwd),
		logDir: canonicalPath(required(env, "PLUTO_LOG_DIR"), cwd),
		evidenceDir: canonicalPath(required(env, "PLUTO_EVIDENCE_DIR"), cwd),
		signingMode: signer ? "command-configured" : key ? "key-configured" : "unsigned-configured",
		signingReference: createHash("sha256").update(JSON.stringify([signer ?? "", key ? canonicalPath(key, cwd) : "", env.PLUTO_PROMOTION_PUBKEY ? canonicalPath(env.PLUTO_PROMOTION_PUBKEY, cwd) : ""])).digest("hex"),
		sandboxMode: required(env, "PLUTO_SANDBOX_MODE"),
	};
}
export function bindingPath(sessionFile: string): string { return `${canonicalPath(sessionFile)}.pluto-binding.json`; }
export function outcomePath(binding: SessionBinding): string { return `${binding.sessionFile}.pluto-outcome.json`; }
function associationEqual(a: EngagementAssociation, b: EngagementAssociation): boolean { return JSON.stringify(a) === JSON.stringify(b); }

export function readBinding(path: string): SessionBinding {
	let raw: unknown;
	try { raw = JSON.parse(readFileSync(path, "utf8")); }
	catch { throw new SessionBindingError(`missing or unreadable descriptor ${path}`); }
	if (!raw || typeof raw !== "object") throw new SessionBindingError("invalid descriptor");
	const b = raw as SessionBinding;
	const a = b.association;
	if (b.schema !== 1 || typeof b.sessionId !== "string" || !b.sessionId || typeof b.sessionFile !== "string" || !a ||
		![a.label, a.host, a.stateDir, a.logDir, a.evidenceDir, a.signingMode, a.signingReference, a.sandboxMode].every(x => typeof x === "string" && x.length > 0) ||
		!Array.isArray(a.scope) || !a.scope.every(x => typeof x === "string") || !["new", "adopted", "fork"].includes(b.origin)) {
		throw new SessionBindingError("invalid descriptor fields");
	}
	if (canonicalPath(b.sessionFile) !== b.sessionFile || bindingPath(b.sessionFile) !== canonicalPath(path)) throw new SessionBindingError("descriptor/session path mismatch");
	return b;
}
/** Exclusive atomic publication: competing equal writers are idempotent; never overwrite. */
export function persistBinding(binding: SessionBinding): SessionBinding {
	const path = bindingPath(binding.sessionFile);
	mkdirSync(dirname(path), { recursive: true });
	const temporary = `${path}.${randomUUID()}.tmp`;
	const fd = openSync(temporary, "wx", 0o600);
	try {
		try { writeFileSync(fd, `${JSON.stringify(binding, null, 2)}\n`); fsyncSync(fd); }
		finally { closeSync(fd); }
		try { linkSync(temporary, path); }
		catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
		const parentFd = openSync(dirname(path), "r");
		try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
	} finally { unlinkSync(temporary); }
	const existing = readBinding(path);
	if (existing.sessionId !== binding.sessionId || !associationEqual(existing.association, binding.association)) throw new SessionBindingError("conflicting descriptor already exists; refusing overwrite");
	return existing;
}

export function assertControlMayRun(binding: SessionBinding, cwd: string, env: NodeJS.ProcessEnv = process.env): void {
	for (const path of [killSwitchPath(cwd, env), join(cwd, "state/KILL_SWITCH"), join(cwd, "state/PAUSED"), join(binding.association.stateDir, "KILL_SWITCH"), join(binding.association.stateDir, "PAUSED")]) {
		if (existsSync(path)) throw new SessionBindingError(`parent control stop is active (${path})`);
	}
}
export function assertParentMayRun(binding: SessionBinding, cwd: string, env: NodeJS.ProcessEnv = process.env): void {
	assertControlMayRun(binding, cwd, env);
	const hold = getProviderHold(binding);
	if (hold.blocked) throw new SessionBindingError(`parent stopped (${hold.reason})`);
}

export function getActiveBinding(cwd: string, env: NodeJS.ProcessEnv = process.env): SessionBinding {
	const association = configuredAssociation(cwd, env); // before opening any ledger
	if (env.PLUTO_PARENT_BINDING_PATH) {
		const parent = readBinding(env.PLUTO_PARENT_BINDING_PATH);
		if (!env.PLUTO_DELEGATE_ID || !/^[A-Za-z0-9-]{1,96}$/.test(env.PLUTO_DELEGATE_ID)) throw new SessionBindingError("ephemeral delegate lacks valid explicit identity");
		if (!associationEqual(parent.association, association)) throw new SessionBindingError("delegate configuration differs from parent");
		assertParentMayRun(parent, cwd, env);
		return parent;
	}
	const file = required(env, "PLUTO_ACTIVE_SESSION_FILE");
	const id = required(env, "PLUTO_ACTIVE_SESSION_ID");
	const binding = readBinding(bindingPath(file));
	if (binding.sessionId !== id || !associationEqual(binding.association, association)) throw new SessionBindingError("active session or engagement configuration differs from saved binding");
	return binding;
}

export interface BindingEntry { type: string; customType?: string; data?: unknown; }
export function bindSession(opts: {
	cwd: string; sessionFile: string | undefined; sessionId: string;
	entries: readonly BindingEntry[]; reason: string; env?: NodeJS.ProcessEnv;
}): SessionBinding {
	const env = opts.env ?? process.env;
	const association = configuredAssociation(opts.cwd, env);
	if (!opts.sessionFile) {
		if (!env.PLUTO_PARENT_BINDING_PATH) throw new SessionBindingError("--no-session requires an inherited parent descriptor");
		return getActiveBinding(opts.cwd, env);
	}
	const file = canonicalPath(opts.sessionFile);
	const path = bindingPath(file);
	const metadata = [...opts.entries].reverse().find(e => e.type === "custom" && e.customType === "pluto-engagement-binding")?.data as SessionBinding | undefined;
	let binding: SessionBinding;
	if (existsSync(path)) {
		binding = readBinding(path);
		if (binding.sessionId !== opts.sessionId || !associationEqual(binding.association, association)) throw new SessionBindingError("saved session binding conflicts with launcher inputs");
		if (metadata && !associationEqual(metadata.association, binding.association)) throw new SessionBindingError("selected branch metadata conflicts with the durable descriptor");
	} else {
		const historical = opts.entries.some(e => e.type === "message");
		const isFork = opts.reason === "fork";
		if (isFork && (!metadata || !associationEqual(metadata.association, association))) throw new SessionBindingError("fork has no matching binding on its selected branch");
		if (isFork && metadata) {
			const parent = readBinding(bindingPath(metadata.sessionFile));
			if (parent.sessionId !== metadata.sessionId || !associationEqual(parent.association, metadata.association)) throw new SessionBindingError("fork selected-branch metadata differs from its parent descriptor");
		}
		if (historical && !isFork && env.PLUTO_ADOPT_SESSION !== "1") throw new SessionBindingError("legacy session is unbound; use explicit launcher --adopt-session with --session");
		if (!isFork && env.PLUTO_LAUNCHER !== "1") throw new SessionBindingError("new binding requires the operator launcher");
		binding = persistBinding({
			schema: 1, sessionId: opts.sessionId, sessionFile: file, association,
			origin: isFork ? "fork" : historical ? "adopted" : "new", createdAt: new Date().toISOString(),
			...(isFork && metadata ? { forkedFrom: { sessionId: metadata.sessionId, sessionFile: metadata.sessionFile, outcomePath: outcomePath(metadata) } } : {}),
		});
	}
	env.PLUTO_ACTIVE_SESSION_FILE = file;
	env.PLUTO_ACTIVE_SESSION_ID = opts.sessionId;
	env.PLUTO_ACTIVE_BINDING_PATH = path;
	delete env.PLUTO_ADOPT_SESSION; // one startup operation, not a later session-switch grant
	return binding;
}
