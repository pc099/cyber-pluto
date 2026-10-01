import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createWriteTool } from "@earendil-works/pi-coding-agent";
import guard from "./index.js";
import { bindSession } from "../state/session-binding.js";
import { resetEngagement } from "../state/engagement.js";

test("startup failure still blocks the actual built-in write tool and model input", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-firstguard-"));
	const saved = { ...process.env };
	const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();
	const api = { on: (name: string, handler: (event: unknown, ctx: ExtensionContext) => unknown) => handlers.set(name, handler), registerCommand: () => {}, appendEntry: () => {} } as unknown as ExtensionAPI;
	const ctx = { cwd, sessionManager: { getSessionFile: () => join(cwd, "session.jsonl"), getSessionId: () => "fixture", getBranch: () => [] } } as unknown as ExtensionContext;
	try {
		for (const key of Object.keys(process.env)) if (key.startsWith("PLUTO_")) delete process.env[key];
		guard(api);
		await handlers.get("session_start")!({ reason: "startup" }, ctx);
		const result = await handlers.get("tool_call")!({ toolName: "write", input: { path: "must-not-exist", content: "fixture" } }, ctx) as { block?: boolean };
		// Intercept the actual built-in executor, not a dummy payload. Full SDK
		// hook dispatch is a separate integration check.
		if (!result?.block) await createWriteTool(cwd).execute("fixture", { path: "must-not-exist", content: "fixture" });
		assert.equal(result.block, true);
		assert.equal(existsSync(join(cwd, "must-not-exist")), false);
		assert.equal(existsSync(join(cwd, "state/pluto.db")), false);
		assert.deepEqual(await handlers.get("input")!({}, ctx), { action: "handled" });
	} finally {
		for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
		Object.assign(process.env, saved);
		rmSync(cwd, { recursive: true, force: true });
	}
});

test("a configured binding cannot allow built-in execution after corrupt-ledger startup failure", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-corrupt-bootstrap-"));
	const saved = { ...process.env };
	const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();
	const api = { on: (name: string, handler: (event: unknown, ctx: ExtensionContext) => unknown) => handlers.set(name, handler), registerCommand: () => {}, appendEntry: () => {} } as unknown as ExtensionAPI;
	const ctx = { cwd, sessionManager: { getSessionFile: () => join(cwd, "session.jsonl"), getSessionId: () => "fixture", getBranch: () => [] } } as unknown as ExtensionContext;
	try {
		for (const key of Object.keys(process.env)) if (key.startsWith("PLUTO_")) delete process.env[key];
		Object.assign(process.env, { PLUTO_TARGET_LABEL: "fixture", PLUTO_TARGET_HOST: "fixture.invalid", PLUTO_SCOPE_HOSTS: "fixture.invalid", PLUTO_STATE_DIR: join(cwd, "state"), PLUTO_LOG_DIR: join(cwd, "logs"), PLUTO_EVIDENCE_DIR: join(cwd, "evidence"), PLUTO_SANDBOX_MODE: "disabled", PLUTO_LAUNCHER: "1" });
		mkdirSync(join(cwd, "state"));
		writeFileSync(join(cwd, "state/pluto.db"), "corrupt fixture ledger");
		guard(api);
		await handlers.get("session_start")!({ reason: "startup" }, ctx);
		const result = await handlers.get("tool_call")!({ toolName: "write", input: { path: "must-not-exist", content: "fixture" } }, ctx) as { block?: boolean; reason?: string };
		if (!result?.block) await createWriteTool(cwd).execute("fixture", { path: "must-not-exist", content: "fixture" });
		assert.equal(result.block, true);
		assert.match(result.reason!, /not a database/);
		assert.equal(existsSync(join(cwd, "must-not-exist")), false);
		assert.deepEqual(await handlers.get("input")!({}, ctx), { action: "handled" });
	} finally {
		resetEngagement();
		for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
		Object.assign(process.env, saved);
		rmSync(cwd, { recursive: true, force: true });
	}
});

test("separate engagement module realms close prior caches before identity rejection", async () => {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-realms-"));
	const saved = { ...process.env };
	const first = await import(`../state/engagement.js?realm=first-${Date.now()}`);
	const second = await import(`../state/engagement.js?realm=second-${Date.now()}`);
	try {
		for (const key of Object.keys(process.env)) if (key.startsWith("PLUTO_")) delete process.env[key];
		Object.assign(process.env, { PLUTO_TARGET_LABEL: "fixture", PLUTO_TARGET_HOST: "fixture.invalid", PLUTO_SCOPE_HOSTS: "fixture.invalid", PLUTO_STATE_DIR: join(cwd, "state"), PLUTO_LOG_DIR: join(cwd, "logs"), PLUTO_EVIDENCE_DIR: join(cwd, "evidence"), PLUTO_SANDBOX_MODE: "disabled", PLUTO_LAUNCHER: "1" });
		bindSession({ cwd, sessionFile: join(cwd, "session.jsonl"), sessionId: "fixture", entries: [], reason: "startup" });
		const oldFirst = first.startEngagement(cwd);
		const oldSecond = second.startEngagement(cwd);
		assert.notEqual(oldFirst.db, oldSecond.db);
		Object.assign(process.env, { PLUTO_TARGET_LABEL: "second", PLUTO_STATE_DIR: join(cwd, "second-state") });
		bindSession({ cwd, sessionFile: join(cwd, "second.jsonl"), sessionId: "second", entries: [], reason: "new" });
		const newFirst = first.startEngagement(cwd);
		const newSecond = second.startEngagement(cwd);
		assert.equal(newFirst.repos.targets.getById(newFirst.targetId)?.label, "second");
		assert.equal(newSecond.repos.targets.getById(newSecond.targetId)?.label, "second");
		assert.throws(() => oldFirst.db.prepare("SELECT 1"));
		assert.throws(() => oldSecond.db.prepare("SELECT 1"));
		delete process.env.PLUTO_ACTIVE_SESSION_ID;
		assert.throws(() => first.startEngagement(cwd), /missing PLUTO_ACTIVE_SESSION_ID/);
		assert.throws(() => second.getEngagement(), /missing PLUTO_ACTIVE_SESSION_ID/);
		assert.throws(() => newFirst.db.prepare("SELECT 1"));
		assert.throws(() => newSecond.db.prepare("SELECT 1"));
		assert.equal(first.getEngagement(), undefined);
		assert.equal(second.getEngagement(), undefined);
	} finally {
		first.resetEngagement(); second.resetEngagement();
		for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
		Object.assign(process.env, saved);
		rmSync(cwd, { recursive: true, force: true });
	}
});
