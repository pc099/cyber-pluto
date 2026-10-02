import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import cockpitExtension from "./index.js";
import { SCHEMA_SQL } from "../state/schema.js";
import { checkSignerHealth } from "../state/signer-health.js";

const commands = new Map<string, { handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> }>();
cockpitExtension({ on: () => {}, registerTool: () => {}, registerCommand: (name: string, cmd: { handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> }) => commands.set(name, cmd) } as unknown as ExtensionAPI);

test("operator kill honors the configured external control path and declined confirmation writes nothing", async () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-kill-command-"));
	const saved = { kill: process.env.PLUTO_KILL_FILE, sandbox: process.env.PLUTO_SANDBOX_MODE };
	try {
		process.env.PLUTO_KILL_FILE = join(root, "control", "KILL_SWITCH");
		process.env.PLUTO_SANDBOX_MODE = "disabled";
		const ctx = (approve: boolean) => ({ cwd: root, ui: { confirm: async () => approve, notify: () => {} } }) as unknown as ExtensionCommandContext;
		await commands.get("kill")!.handler("", ctx(false));
		assert.equal(existsSync(process.env.PLUTO_KILL_FILE), false);
		await commands.get("kill")!.handler("", ctx(true));
		assert.match(readFileSync(process.env.PLUTO_KILL_FILE, "utf8"), /engaged by operator/);
		assert.equal(existsSync(join(root, "state", "KILL_SWITCH")), false);
	} finally {
		for (const [key, value] of [["PLUTO_KILL_FILE", saved.kill], ["PLUTO_SANDBOX_MODE", saved.sandbox]]) {
			if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
		}
		rmSync(root, { recursive: true, force: true });
	}
});

test("sandbox kill refuses missing protected endpoint without writing a workspace stop", async () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-kill-missing-"));
	const saved = { socket: process.env.PLUTO_PROMOTION_SIGNER_SOCK, sandbox: process.env.PLUTO_SANDBOX_MODE };
	try {
		delete process.env.PLUTO_PROMOTION_SIGNER_SOCK;
		process.env.PLUTO_SANDBOX_MODE = "requested";
		const ctx = { cwd: root, ui: { confirm: async () => true, notify: () => {} } } as unknown as ExtensionCommandContext;
		await assert.rejects(commands.get("kill")!.handler("", ctx), /no configured signing\/control endpoint/);
		assert.equal(existsSync(join(root, "state", "KILL_SWITCH")), false);
	} finally {
		for (const [key, value] of [["PLUTO_PROMOTION_SIGNER_SOCK", saved.socket], ["PLUTO_SANDBOX_MODE", saved.sandbox]]) {
			if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
		}
		rmSync(root, { recursive: true, force: true });
	}
});

test("confirmed sandbox operator command engages only the daemon's protected stop path", { skip: process.getuid?.() !== 0 }, async () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-kill-daemon-"));
	const state = join(root, "state");
	const control = join(root, "control");
	mkdirSync(state); mkdirSync(control);
	const db = new DatabaseSync(join(state, "pluto.db")); db.exec(SCHEMA_SQL); db.close();
	const keys = generateKeyPairSync("ed25519");
	const priv = join(root, "private.key"), pub = join(root, "public.pub"), sock = join(root, "sign.sock"), kill = join(control, "KILL_SWITCH");
	writeFileSync(priv, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o400 });
	writeFileSync(pub, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o444 });
	const daemon = spawn(process.execPath, [fileURLToPath(new URL("../state/promotion-sign-daemon.js", import.meta.url)), sock], { stdio: "ignore", env: { ...process.env, PLUTO_STATE_DIR: state, PLUTO_CWD: root, PLUTO_PROMOTION_PRIVKEY: priv, PLUTO_PROMOTION_PUBKEY: pub, PLUTO_SIGNER_STRICT: "1", PLUTO_SIGNER_RUN_ID: "kill-fixture", PLUTO_KILL_FILE: kill } });
	const completed = new Promise<void>(resolve => daemon.once("exit", () => resolve()));
	const saved = { socket: process.env.PLUTO_PROMOTION_SIGNER_SOCK, mode: process.env.PLUTO_SANDBOX_MODE, kill: process.env.PLUTO_KILL_FILE };
	try {
		const deadline = Date.now() + 5000;
		while (true) {
			try { await checkSignerHealth({ socketPath: sock, ledgerPath: join(state, "pluto.db"), runId: "kill-fixture", publicKeyPath: pub }); break; }
			catch (error) { if (Date.now() > deadline) throw error; await sleep(20); }
		}
		Object.assign(process.env, { PLUTO_PROMOTION_SIGNER_SOCK: sock, PLUTO_SANDBOX_MODE: "requested", PLUTO_KILL_FILE: join(root, "caller-selected-path") });
		const ctx = { cwd: root, ui: { confirm: async () => true, notify: () => {} } } as unknown as ExtensionCommandContext;
		await commands.get("kill")!.handler("", ctx);
		assert.match(readFileSync(kill, "utf8"), /signer operator stop/);
		assert.equal(statSync(kill).uid, 0);
		assert.equal(existsSync(process.env.PLUTO_KILL_FILE!), false, "caller cannot choose the root write destination");
		assert.equal(existsSync(join(root, "state", "KILL_SWITCH")), false);
	} finally {
		daemon.kill("SIGTERM");
		await Promise.race([completed, sleep(3000).then(() => { daemon.kill("SIGKILL"); })]);
		for (const [key, value] of [["PLUTO_PROMOTION_SIGNER_SOCK", saved.socket], ["PLUTO_SANDBOX_MODE", saved.mode], ["PLUTO_KILL_FILE", saved.kill]]) {
			if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
		}
		rmSync(root, { recursive: true, force: true });
	}
});
