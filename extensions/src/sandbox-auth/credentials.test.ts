import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { injectCodexAccessToken } from "./credentials.js";
import sandboxAuthExtension from "./index.js";

test("injection forwards only a valid bounded access token and refuses expiry/private-file failures", () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-auth-"));
	const file = join(dir, "auth.json");
	try {
		const data = JSON.stringify({ "openai-codex": { type: "oauth", access: "synthetic-access", refresh: "never-forward", expires: 900_000 }, other: { key: "never-forward" } });
		writeFileSync(file, data, { mode: 0o600 });
		const env: NodeJS.ProcessEnv = {};
		injectCodexAccessToken(env, file, 0);
		assert.deepEqual(env, { PLUTO_CODEX_ACCESS_TOKEN: "synthetic-access", PLUTO_CODEX_ACCESS_EXPIRES: "900000" });
		assert.equal(readFileSync(file, "utf8"), data);
		assert.throws(() => injectCodexAccessToken({}, file, 800_000), /expired or near expiry/);
		const alias = join(dir, "alias.json");
		symlinkSync(file, alias);
		assert.throws(() => injectCodexAccessToken({}, alias, 0), /aliased/);
		chmodSync(dir, 0o777);
		assert.throws(() => injectCodexAccessToken({}, file, 0), /unsafe root-controlled/);
		chmodSync(dir, 0o700);
		chmodSync(file, 0o644);
		assert.throws(() => injectCodexAccessToken({}, file, 0), /root-owned private/);
	} finally { rmSync(dir, { recursive: true, force: true }); }
});

test("provider override is sandbox-only, env-referenced and never passes the literal token", () => {
	const saved = { mode: process.env.PLUTO_SANDBOX_MODE, token: process.env.PLUTO_CODEX_ACCESS_TOKEN, expires: process.env.PLUTO_CODEX_ACCESS_EXPIRES };
	const calls: unknown[][] = [];
	const pi = { registerProvider: (...args: unknown[]) => calls.push(args) } as unknown as ExtensionAPI;
	try {
		process.env.PLUTO_CODEX_ACCESS_TOKEN = "synthetic-access";
		process.env.PLUTO_CODEX_ACCESS_EXPIRES = String(Date.now() + 900_000);
		process.env.PLUTO_SANDBOX_MODE = "disabled";
		sandboxAuthExtension(pi);
		assert.equal(calls.length, 0);
		process.env.PLUTO_SANDBOX_MODE = "requested";
		sandboxAuthExtension(pi);
		assert.deepEqual(calls, [["openai-codex", { apiKey: "$PLUTO_CODEX_ACCESS_TOKEN" }]]);
		process.env.PLUTO_CODEX_ACCESS_EXPIRES = "0";
		assert.throws(() => sandboxAuthExtension(pi), /expired/);
	} finally {
		for (const [key, value] of [["PLUTO_SANDBOX_MODE", saved.mode], ["PLUTO_CODEX_ACCESS_TOKEN", saved.token], ["PLUTO_CODEX_ACCESS_EXPIRES", saved.expires]]) {
			if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
		}
	}
});
