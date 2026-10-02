import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { bindSession, getActiveBinding, bindingPath, configuredAssociation, persistBinding, canonicalPath } from "./session-binding.js";
import { buildSubAgentEnv } from "../delegation/spawn.js";
import { initializeOutcome, recordProviderError, recordHardCap } from "../lifecycle/provider-outcome.js";

function fixture() {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-binding-"));
	const env: NodeJS.ProcessEnv = {
		PLUTO_TARGET_LABEL: "fixture", PLUTO_TARGET_HOST: "fixture.invalid", PLUTO_SCOPE_HOSTS: "fixture.invalid",
		PLUTO_STATE_DIR: join(cwd, "state"), PLUTO_LOG_DIR: join(cwd, "logs"), PLUTO_EVIDENCE_DIR: join(cwd, "evidence"),
		PLUTO_SANDBOX_MODE: "disabled", PLUTO_LAUNCHER: "1",
	};
	const options = { cwd, env, sessionFile: join(cwd, "sessions", "fixture.jsonl"), sessionId: "fixture-id", entries: [], reason: "startup" };
	return { cwd, env, options, cleanup: () => rmSync(cwd, { recursive: true, force: true }) };
}

test("new binding is durable before any assistant response and repeats idempotently", () => {
	const f = fixture();
	try {
		const b = bindSession(f.options);
		assert.ok(existsSync(bindingPath(b.sessionFile)));
		assert.equal(existsSync(b.sessionFile), false);
		assert.deepEqual(getActiveBinding(f.cwd, f.env), b);
		assert.deepEqual(bindSession(f.options), b);
		assert.equal(existsSync(join(f.cwd, "state/pluto.db")), false);
	} finally { f.cleanup(); }
});

test("missing inputs and changed identity fail without a fallback ledger", () => {
	const f = fixture();
	try {
		assert.throws(() => configuredAssociation(f.cwd, {}), /missing PLUTO_TARGET_LABEL/);
		const b = bindSession(f.options);
		for (const [key, value] of [["PLUTO_STATE_DIR", join(f.cwd, "other")], ["PLUTO_TARGET_HOST", "other.invalid"], ["PLUTO_ACTIVE_SESSION_ID", "different"], ["PLUTO_SANDBOX_MODE", "requested"]]) {
			assert.throws(() => getActiveBinding(f.cwd, { ...f.env, [key!]: value! }), /binding blocked/);
		}
		assert.equal(existsSync(join(f.cwd, "state/pluto.db")), false);
		assert.equal(readFileSync(bindingPath(b.sessionFile), "utf8").includes('"fixture.invalid"'), true);
	} finally { f.cleanup(); }
});

test("existing writer conflicts and corrupt descriptors never get overwritten", () => {
	const f = fixture();
	try {
		const b = bindSession(f.options);
		const original = readFileSync(bindingPath(b.sessionFile), "utf8");
		assert.throws(() => persistBinding({ ...b, sessionId: "conflict" }), /conflicting/);
		assert.equal(readFileSync(bindingPath(b.sessionFile), "utf8"), original);
		writeFileSync(bindingPath(b.sessionFile), "{torn");
		assert.throws(() => bindSession(f.options), /unreadable/);
		assert.equal(readFileSync(bindingPath(b.sessionFile), "utf8"), "{torn");
	} finally { f.cleanup(); }
});

test("legacy adoption is explicit and cannot authorize a later session switch", () => {
	const f = fixture();
	try {
		const options = { ...f.options, entries: [{ type: "message" }], reason: "resume" };
		assert.throws(() => bindSession(options), /legacy session is unbound/);
		f.env.PLUTO_ADOPT_SESSION = "1";
		assert.equal(bindSession(options).origin, "adopted");
		assert.equal(f.env.PLUTO_ADOPT_SESSION, undefined);
		assert.throws(() => bindSession({ ...options, sessionFile: join(f.cwd, "sessions/another.jsonl"), sessionId: "another" }), /legacy/);
	} finally { f.cleanup(); }
});

test("fork inherits selected-branch association and new identity with interruption provenance", () => {
	const f = fixture();
	try {
		const parent = bindSession(f.options);
		const branch = [{ type: "custom", customType: "pluto-engagement-binding", data: parent }, { type: "message" }];
		const fork = bindSession({ ...f.options, sessionId: "fork-id", sessionFile: join(f.cwd, "sessions/fork.jsonl"), entries: branch, reason: "fork" });
		assert.equal(fork.origin, "fork");
		assert.equal(fork.sessionId, "fork-id");
		assert.deepEqual(fork.association, parent.association);
		assert.equal(fork.forkedFrom?.sessionId, parent.sessionId);
		assert.throws(() => bindSession({ ...f.options, sessionId: "emptyfork", sessionFile: join(f.cwd, "sessions/emptyfork.jsonl"), entries: [], reason: "fork" }), /selected branch/);
		const foreign = { ...parent, sessionId: "foreign-session" };
		assert.throws(() => bindSession({ ...f.options, sessionId: "foreignfork", sessionFile: join(f.cwd, "sessions/foreignfork.jsonl"), entries: [{ type: "custom", customType: "pluto-engagement-binding", data: foreign }], reason: "fork" }), /parent descriptor/);
		assert.throws(() => bindSession({ ...f.options, entries: [{ type: "custom", customType: "pluto-engagement-binding", data: { ...parent, association: { ...parent.association, host: "wrong.invalid" } } }], reason: "resume" }), /branch metadata conflicts/);
	} finally { f.cleanup(); }
});

test("canonical unborn paths resolve symlinked parents to the actual workspace", () => {
	const f = fixture();
	try {
		mkdirSync(join(f.cwd, "actual"));
		symlinkSync(join(f.cwd, "actual"), join(f.cwd, "alias"));
		assert.equal(canonicalPath(join(f.cwd, "alias/unborn.jsonl")), join(f.cwd, "actual/unborn.jsonl"));
	} finally { f.cleanup(); }
});

test("ephemeral delegates require a bound parent and obey persisted parent stops", () => {
	const f = fixture();
	try {
		assert.throws(() => bindSession({ ...f.options, sessionFile: undefined }), /inherited parent/);
		const b = bindSession(f.options);
		initializeOutcome(b);
		const child = buildSubAgentEnv(f.cwd, f.env);
		assert.deepEqual(getActiveBinding(f.cwd, child), b);
		assert.throws(() => getActiveBinding(f.cwd, { ...child, PLUTO_STATE_DIR: join(f.cwd, "wrong") }), /differs from parent/);
		recordProviderError(b, { category: "provider_blocked", summary: "synthetic policy rejection", fingerprint: "fixture" });
		assert.throws(() => getActiveBinding(f.cwd, child), /parent stopped/);
		assert.throws(() => buildSubAgentEnv(f.cwd, f.env), /parent stopped/);
	} finally { f.cleanup(); }
});

test("delegates reject corrupt parent outcomes, hard caps and bound pause controls", () => {
	for (const stop of ["corrupt", "cap", "pause"]) {
		const f = fixture();
		try {
			const b = bindSession(f.options);
			const child = buildSubAgentEnv(f.cwd, f.env);
			if (stop === "corrupt") writeFileSync(`${b.sessionFile}.pluto-outcome.json`, "{torn");
			if (stop === "cap") recordHardCap(b, "hard_cap:wall_clock");
			if (stop === "pause") { mkdirSync(b.association.stateDir); writeFileSync(join(b.association.stateDir, "PAUSED"), "operator pause"); }
			assert.throws(() => getActiveBinding(f.cwd, child));
		} finally { f.cleanup(); }
	}
});

test("delegates inherit the external trusted kill path and refuse an active stop", () => {
	const f = fixture();
	try {
		f.env.PLUTO_KILL_FILE = join(f.cwd, "trusted-control", "KILL_SWITCH");
		bindSession(f.options);
		const child = buildSubAgentEnv(f.cwd, f.env);
		assert.equal(child.PLUTO_KILL_FILE, f.env.PLUTO_KILL_FILE);
		mkdirSync(join(f.cwd, "trusted-control"));
		writeFileSync(f.env.PLUTO_KILL_FILE, "operator stop");
		assert.throws(() => getActiveBinding(f.cwd, child), /parent control stop/);
		assert.throws(() => buildSubAgentEnv(f.cwd, f.env), /parent control stop/);
	} finally { f.cleanup(); }
});

test("a specialist's own policy hold blocks direct nested spawn while transient errors remain distinct", () => {
	const f = fixture();
	try {
		const root = bindSession(f.options);
		initializeOutcome(root);
		const child = buildSubAgentEnv(f.cwd, f.env);
		const own = { sessionId: child.PLUTO_DELEGATE_ID!, sessionFile: `${root.sessionFile}.delegate-${child.PLUTO_DELEGATE_ID}` };
		initializeOutcome(own);
		recordProviderError(own, { category: "network", summary: "synthetic network error", fingerprint: "network-fixture" });
		assert.ok(buildSubAgentEnv(f.cwd, child).PLUTO_DELEGATE_ID);
		recordProviderError(own, { category: "provider_blocked", summary: "synthetic policy error", fingerprint: "policy-fixture" });
		assert.throws(() => buildSubAgentEnv(f.cwd, child), /calling specialist is held/);
		assert.throws(() => getActiveBinding(f.cwd, { ...child, PLUTO_DELEGATE_ID: "../../bad" }), /valid explicit identity/);
	} finally { f.cleanup(); }
});
