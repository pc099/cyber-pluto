import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildPlan } from "./index.js";
import { acquireLaunchLock, cleanupSandbox, uidQuiescence, waitForLedgerProbe, waitForSandboxReadiness, type CleanupOperations } from "./sandbox.js";
import { assertSandboxVerifierPath, assertWorkspaceControls, preflightSandboxSession, sandboxEnvironment, selectedBindingMetadata, verifyKeypair } from "./sandbox-preflight.js";
import { configuredAssociation, persistBinding, type SessionBinding } from "../state/session-binding.js";
import { initializeOutcome, recordProviderError } from "../lifecycle/provider-outcome.js";

test("readiness selection implies confinement, cannot adopt history or generate an autonomous prompt", () => {
	const result = buildPlan(["fixture.invalid", "--sandbox-check", "--headless"]);
	assert.equal(result.kind, "plan");
	if (result.kind !== "plan") throw new Error("missing plan");
	assert.equal(result.plan.sandbox, true); assert.equal(result.plan.sandboxCheck, true);
	assert.equal(result.plan.cliArgs.includes("-p"), false);
	assert.equal(result.plan.env.PLUTO_STATE_DIR, "/var/lib/cyber-pluto/engagements/engagement-fixture-invalid/state");
	assert.equal(buildPlan(["fixture.invalid", "--sandbox", "--session", "legacy.jsonl", "--adopt-session"]).kind, "error");
});

test("sandbox configuration removes stale authority/identity overrides and uses identical canonical roots", () => {
	const env = sandboxEnvironment({ PLUTO_PROMOTION_PRIVKEY: "/root/key", PLUTO_ACTIVE_SESSION_ID: "stale", PLUTO_KILL_FILE: "/tmp/stop", PLUTO_CODEX_ACCESS_TOKEN: "stale", OPENAI_API_KEY: "fixture-key" }, { PLUTO_TARGET_LABEL: "fixture" }, "/opt/cyber-pluto", "/var/lib/cyber-pluto/engagements/fixture", "/run/cyber-pluto/signers/fixture", "/etc/cyber-pluto/promotion_ed25519.pub");
	assert.equal(env.PLUTO_PROMOTION_PRIVKEY, undefined); assert.equal(env.PLUTO_ACTIVE_SESSION_ID, undefined); assert.equal(env.PLUTO_CODEX_ACCESS_TOKEN, undefined);
	assert.equal(env.PLUTO_KILL_FILE, "/var/lib/cyber-pluto/control/KILL_SWITCH");
	assert.equal(env.PLUTO_STATE_DIR, "/var/lib/cyber-pluto/engagements/fixture/state");
	assert.equal(env.PI_CODING_AGENT_DIR, "/var/lib/cyber-pluto/engagements/fixture/pi-agent");
	assert.equal(env.OPENAI_API_KEY, "fixture-key");
	assert.match(env.PLUTO_PROMOTION_SIGNER_CMD!, /\/run\/cyber-pluto\/signers\/fixture\/promotion.sock$/);
});

function sessionFixture() {
	const root = mkdtempSync(join(tmpdir(), "pluto-sandbox-session-"));
	const sessions = join(root, "sessions"); mkdirSync(sessions);
	const file = join(sessions, "session.jsonl");
	const env = { PLUTO_TARGET_LABEL: "fixture", PLUTO_TARGET_HOST: "fixture.invalid", PLUTO_SCOPE_HOSTS: "fixture.invalid", PLUTO_STATE_DIR: join(root, "state"), PLUTO_LOG_DIR: join(root, "logs"), PLUTO_EVIDENCE_DIR: join(root, "evidence"), PLUTO_SANDBOX_MODE: "requested", PLUTO_PROMOTION_SIGNER_CMD: "node /opt/cyber-pluto/client.js /run/cyber-pluto/signers/fixture/promotion.sock", PLUTO_PROMOTION_PUBKEY: "/etc/cyber-pluto/promotion_ed25519.pub" };
	const binding: SessionBinding = { schema: 1, sessionId: "fixture-session", sessionFile: file, association: configuredAssociation(root, env), origin: "new", createdAt: new Date().toISOString() };
	writeFileSync(file, JSON.stringify({ type: "session", id: binding.sessionId, version: 3 }) + "\n" + JSON.stringify({ type: "custom", id: "binding", parentId: null, customType: "pluto-engagement-binding", data: binding }) + "\n");
	persistBinding(binding);
	return { root, sessions, file, env, binding };
}

test("unchanged association resumes; conversion and external relocation refuse without modifying descriptors", () => {
	const fixture = sessionFixture();
	try {
		const bytes = readFileSync(`${fixture.file}.pluto-binding.json`, "utf8");
		assert.equal(preflightSandboxSession(fixture.file, fixture.root, fixture.env, fixture.sessions).sessionId, fixture.binding.sessionId);
		assert.throws(() => preflightSandboxSession(fixture.file, fixture.root, { ...fixture.env, PLUTO_SANDBOX_MODE: "disabled" }, fixture.sessions), /conversion\/relocation/);
		const destination = join(fixture.root, "new-sessions");
		assert.throws(() => preflightSandboxSession(fixture.file, fixture.root, fixture.env, destination), /relocation\/conversion/);
		assert.equal(existsSync(destination), false);
		assert.equal(readFileSync(`${fixture.file}.pluto-binding.json`, "utf8"), bytes);
	} finally { rmSync(fixture.root, { recursive: true, force: true }); }
});

test("selected branch disagreement and persisted provider hold refuse without clearing either", () => {
	const fixture = sessionFixture();
	try {
		initializeOutcome(fixture.binding);
		recordProviderError(fixture.binding, { category: "provider_blocked", summary: "fixture interruption", fingerprint: "fixture" });
		const outcome = readFileSync(`${fixture.file}.pluto-outcome.json`, "utf8");
		assert.throws(() => preflightSandboxSession(fixture.file, fixture.root, fixture.env, fixture.sessions), /provider_blocked/);
		assert.equal(readFileSync(`${fixture.file}.pluto-outcome.json`, "utf8"), outcome);
		assert.equal(preflightSandboxSession(fixture.file, fixture.root, fixture.env, fixture.sessions, { allowHeldDiagnostics: true }).sessionId, fixture.binding.sessionId);
		assert.equal(readFileSync(`${fixture.file}.pluto-outcome.json`, "utf8"), outcome);
		writeFileSync(fixture.file, readFileSync(fixture.file, "utf8") + JSON.stringify({ type: "custom", id: "other", parentId: null, customType: "pluto-engagement-binding", data: { ...fixture.binding, association: { ...fixture.binding.association, host: "different.invalid" } } }) + "\n");
		assert.throws(() => preflightSandboxSession(fixture.file, fixture.root, fixture.env, fixture.sessions), /Selected Pi branch conflicts/);
	} finally { rmSync(fixture.root, { recursive: true, force: true }); }
});

test("persisted environmental pause permits only validated interactive resume diagnostics; kill always refuses", () => {
	const fixture = sessionFixture();
	try {
		mkdirSync(join(fixture.root, "state"));
		const pause = join(fixture.root, "state/PAUSED");
		writeFileSync(pause, "retained environmental pause");
		const selectedBinding = preflightSandboxSession(fixture.file, fixture.root, fixture.env, fixture.sessions);
		assert.doesNotThrow(() => assertWorkspaceControls(fixture.root, { selectedBinding, headless: false, sandboxCheck: false }));
		for (const options of [
			{ selectedBinding, headless: true, sandboxCheck: false },
			{ selectedBinding, headless: false, sandboxCheck: true },
			{ headless: false, sandboxCheck: false },
			{ selectedBinding: { ...selectedBinding, association: { ...selectedBinding.association, stateDir: join(fixture.root, "another-state") } }, headless: false, sandboxCheck: false },
		]) assert.throws(() => assertWorkspaceControls(fixture.root, options), /PAUSED/);
		assert.equal(readFileSync(pause, "utf8"), "retained environmental pause");
		writeFileSync(join(fixture.root, "state/KILL_SWITCH"), "operator stop");
		assert.throws(() => assertWorkspaceControls(fixture.root, { selectedBinding, headless: false, sandboxCheck: false }), /KILL_SWITCH/);
	} finally { rmSync(fixture.root, { recursive: true, force: true }); }
});

test("preflight transcript parsing rejects missing parents and format migration without opening Pi", () => {
	const fixture = sessionFixture();
	try {
		writeFileSync(fixture.file, JSON.stringify({ type: "session", id: "fixture", version: 3 }) + "\n" + JSON.stringify({ type: "message", id: "leaf", parentId: "missing" }) + "\n");
		assert.throws(() => selectedBindingMetadata(fixture.file), /Missing parent/);
		writeFileSync(fixture.file, JSON.stringify({ type: "session", id: "fixture", version: 2 }) + "\n");
		assert.throws(() => selectedBindingMetadata(fixture.file), /format migration is separate/);
	} finally { rmSync(fixture.root, { recursive: true, force: true }); }
});

test("exclusive launch lock refuses competing and stale ownership without removing resources", () => {
	const directory = mkdtempSync(join(tmpdir(), "pluto-sandbox-lock-"));
	try {
		const release = acquireLaunchLock(directory, "first");
		assert.throws(() => acquireLaunchLock(directory, "second"), /EEXIST/);
		assert.equal(JSON.parse(readFileSync(join(directory, "launch.lock/owner.json"), "utf8")).runId, "first");
		release(); assert.equal(existsSync(join(directory, "launch.lock")), false);
	} finally { rmSync(directory, { recursive: true, force: true }); }
});

function cleanupFixture(overrides: Partial<CleanupOperations> = {}) {
	const events: string[] = [];
	const ops: CleanupOperations = {
		stopChild: async () => { events.push("child"); return true; },
		stopSigner: async () => { events.push("signer"); return true; },
		quiescence: () => { events.push("quiescence"); return { known: true, pids: [] }; },
		teardownEgress: () => { events.push("egress"); return true; },
		recovery: () => { events.push("recovery"); }, release: () => { events.push("release"); }, ...overrides,
	};
	return { events, ops };
}

test("cleanup waits for child and signer and confirmed UID quiescence before policy removal", async () => {
	const fixture = cleanupFixture();
	assert.equal(await cleanupSandbox(fixture.ops, true), true);
	assert.deepEqual(fixture.events, ["child", "signer", "quiescence", "egress", "release"]);
});

test("production dispatch retains policy/lock/recovery even after owned processes settle", async () => {
	const fixture = cleanupFixture();
	assert.equal(await cleanupSandbox(fixture.ops, true, true), false);
	assert.deepEqual(fixture.events, ["child", "signer", "recovery"]);
});

test("unknown/remaining workloads and failed teardown retain policy/lock with recovery", async () => {
	for (const quiet of [{ known: false, pids: [] }, { known: true, pids: [42] }]) {
		const fixture = cleanupFixture({ quiescence: () => quiet });
		assert.equal(await cleanupSandbox(fixture.ops, true), false);
		assert.deepEqual(fixture.events, ["child", "signer", "recovery"]);
	}
	const failed = cleanupFixture({ teardownEgress: () => false });
	assert.equal(await cleanupSandbox(failed.ops, true), false);
	assert.deepEqual(failed.events, ["child", "signer", "quiescence", "recovery"]);
});

test("startup signal arriving during awaited health prevents post-readiness child dispatch", async () => {
	let interrupted = false;
	let resolveHealth!: () => void;
	const health = new Promise<void>(resolve => { resolveHealth = resolve; });
	let dispatches = 0;
	const startup = waitForSandboxReadiness(() => health, () => interrupted).then(() => { dispatches++; });
	interrupted = true; resolveHealth();
	await assert.rejects(startup, /interrupted/);
	assert.equal(dispatches, 0);
	await waitForSandboxReadiness(async () => undefined, () => false);
});

test("owned ledger readiness is bounded and refuses nonzero completion", async () => {
	await waitForLedgerProbe(Promise.resolve(0));
	await assert.rejects(waitForLedgerProbe(Promise.resolve(1)), /readiness failed/);
	await assert.rejects(waitForLedgerProbe(new Promise<number>(() => {}), 10), /timed out/);
});

test("UID inventory includes effective/fs identities and fails closed on unreadable inventory", () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-sandbox-proc-"));
	try {
		mkdirSync(join(root, "1")); writeFileSync(join(root, "1/status"), "Name: fixture\nUid:\t0\t994\t0\t994\n");
		mkdirSync(join(root, "2")); writeFileSync(join(root, "2/status"), "Uid:\t0\t0\t0\t0\n");
		assert.deepEqual(uidQuiescence(994, root), { known: true, pids: [1] });
		writeFileSync(join(root, "2/status"), "invalid status");
		assert.equal(uidQuiescence(994, root).known, false);
		assert.equal(uidQuiescence(994, join(root, "missing")).known, false);
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("matching root-only keys pass and mismatched/publicly readable private keys refuse", () => {
	// Keys need protected ancestors; the test checkout is root-owned, unlike /tmp.
	const root = mkdtempSync(join(process.cwd(), ".sandbox-key-fixture-"));
	try {
		chmodSync(root, 0o755);
		const first = generateKeyPairSync("ed25519"); const second = generateKeyPairSync("ed25519");
		const privatePath = join(root, "private.key"); const publicPath = join(root, "public.pub");
		writeFileSync(privatePath, first.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o400 });
		writeFileSync(publicPath, first.publicKey.export({ format: "pem", type: "spki" }), { mode: 0o444 });
		verifyKeypair(privatePath, publicPath);
		chmodSync(publicPath, 0o400);
		assert.throws(() => verifyKeypair(privatePath, publicPath), /world-readable/);
		chmodSync(publicPath, 0o444);
		chmodSync(root, 0o700);
		assert.throws(() => verifyKeypair(privatePath, publicPath), /parents must be traversable/);
		chmodSync(root, 0o755);
		chmodSync(publicPath, 0o600);
		writeFileSync(publicPath, second.publicKey.export({ format: "pem", type: "spki" }));
		chmodSync(publicPath, 0o444);
		assert.throws(() => verifyKeypair(privatePath, publicPath), /keypair mismatch/);
		chmodSync(privatePath, 0o444);
		assert.throws(() => verifyKeypair(privatePath, publicPath), /root-only/);
		const alias = join(root, "alias.key"); symlinkSync(privatePath, alias);
		assert.throws(() => verifyKeypair(alias, publicPath), /symlink/);
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("sandbox verifying key paths must remain visible through private mount trees", () => {
	for (const path of ["/root/public.pub", "/tmp/public.pub", "/run/public.pub", "/root", "/tmp", "/run"]) {
		assert.throws(() => assertSandboxVerifierPath(path), /hidden by the sandbox/);
	}
	assertSandboxVerifierPath("/etc/cyber-pluto/promotion_ed25519.pub");
	assertSandboxVerifierPath("/opt/cyber-pluto/public.pub");
	assertSandboxVerifierPath("/runtime-visible/public.pub");
});
