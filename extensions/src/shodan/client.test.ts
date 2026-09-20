/**
 * Shodan client fixtures QA requires but that need fine control (malformed body,
 * a hanging server → timeout, missing key). Never hits the real API.
 */
import assert from "node:assert/strict";
import { type Server, createServer } from "node:http";
import { after, before, test } from "node:test";
import { fetchShodanHost } from "./client.js";

let server: Server;
let base: string;
let mode: "malformed" | "hang" = "malformed";

before(async () => {
	server = createServer((_req, res) => {
		if (mode === "hang") return; // never respond
		res.writeHead(200, { "content-type": "application/json" });
		res.end("this is not json {{{");
	});
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
	const addr = server.address();
	base = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
});

after(() => server?.close());

test("no key configured fails cleanly without a request", async () => {
	const r = await fetchShodanHost("10.0.0.1", { key: "", base });
	assert.equal(r.ok, false);
	assert.match((r as { error: string }).error, /no SHODAN_API_KEY/);
});

test("a malformed body is reported, not thrown", async () => {
	mode = "malformed";
	const r = await fetchShodanHost("10.0.0.1", { key: "k", base });
	assert.equal(r.ok, false);
	assert.match((r as { error: string }).error, /malformed JSON/);
});

test("a hanging server trips the timeout instead of blocking forever", async () => {
	mode = "hang";
	const r = await fetchShodanHost("10.0.0.1", { key: "k", base, timeoutMs: 150 });
	assert.equal(r.ok, false);
	assert.match((r as { error: string }).error, /timed out/);
});
