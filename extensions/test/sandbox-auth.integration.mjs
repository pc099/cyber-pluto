import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthStorage } from "../../pi/pi/packages/coding-agent/dist/core/auth-storage.js";
import { ModelRuntime } from "../../pi/pi/packages/coding-agent/dist/core/model-runtime.js";
import sandboxAuthExtension from "../dist/sandbox-auth/index.js";

test("actual Pi Codex provider consumes env-only access token and derives account header without OAuth refresh", async () => {
	const names = ["PLUTO_SANDBOX_MODE", "PLUTO_CODEX_ACCESS_TOKEN", "PLUTO_CODEX_ACCESS_EXPIRES"];
	const saved = Object.fromEntries(names.map(name => [name, process.env[name]]));
	const expires = Date.now() + 900_000;
	const payload = { "https://api.openai.com/auth": { chatgpt_account_id: "fixture-account" }, exp: Math.floor(expires / 1000) };
	const token = `synthetic.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.synthetic`;
	try {
		Object.assign(process.env, { PLUTO_SANDBOX_MODE: "requested", PLUTO_CODEX_ACCESS_TOKEN: token, PLUTO_CODEX_ACCESS_EXPIRES: String(expires) });
		const credentials = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({ credentials, modelsPath: null, refreshOnCreate: false });
		sandboxAuthExtension({ registerProvider: (name, config) => runtime.registerProvider(name, config) });
		const model = runtime.getModels("openai-codex")[0];
		assert.ok(model);
		const auth = await runtime.getAuth(model);
		assert.equal(auth.auth.apiKey, token);
		let calls = 0;
		const stream = runtime.streamSimple(model, { messages: [{ role: "user", content: "synthetic auth fixture", timestamp: Date.now() }] }, {
			transport: "sse",
			fetch: async (url, init) => {
				calls++;
				assert.match(String(url), /^https:\/\/chatgpt\.com\/backend-api\//);
				const headers = new Headers(init.headers);
				assert.equal(headers.get("Authorization"), `Bearer ${token}`);
				assert.equal(headers.get("chatgpt-account-id"), "fixture-account");
				return new Response(JSON.stringify({ error: { message: "synthetic test refusal" } }), { status: 403, headers: { "Content-Type": "application/json" } });
			},
		});
		const result = await stream.result();
		assert.equal(result.stopReason, "error");
		assert.equal(calls, 1);
		assert.equal(await credentials.read("openai-codex"), undefined);
	} finally {
		for (const name of names) { if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name]; }
	}
});
