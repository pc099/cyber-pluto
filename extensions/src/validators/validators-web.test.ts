/**
 * Both-paths tests for the command-injection, path-traversal, and reflected-XSS
 * validators (gate logic → prove pass AND reject). Uses an inline vulnerable
 * fixture (mirroring lab/web-vulns/app.mjs) so the suite is hermetic and inside
 * the TS rootDir. XSS needs a headless browser and skips cleanly without one.
 */
import assert from "node:assert/strict";
import { execFileSync, execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { validateCommandInjection } from "./command-injection.js";
import { validatePathTraversal } from "./path-traversal.js";
import { validateXss } from "./xss.js";

const DOCROOT = "/tmp";

function fixtureApp(): Server {
	return createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		const v = (k: string) => url.searchParams.get(k) ?? "";
		const send = (s: number, t: string, b: string) => {
			res.writeHead(s, { "content-type": t });
			res.end(b);
		};
		try {
			switch (url.pathname) {
				case "/ping":
					return send(200, "text/plain", execSync(`echo pinging ${v("host")}`, { shell: "/bin/bash", timeout: 5000 }).toString());
				case "/ping-safe":
					return send(200, "text/plain", `pinging ${v("host")}\n`);
				case "/file":
					return send(200, "text/plain", readFileSync(join(DOCROOT, v("name"))).toString().slice(0, 4000));
				case "/file-safe": {
					const target = resolve(DOCROOT, v("name"));
					if (!target.startsWith(`${resolve(DOCROOT)}/`)) return send(400, "text/plain", "denied");
					return send(200, "text/plain", readFileSync(target).toString().slice(0, 4000));
				}
				case "/greet":
					return send(200, "text/html", `<html><head><title>greet</title></head><body><h1>Hello ${v("name")}</h1></body></html>`);
				case "/greet-safe":
					return send(200, "text/html", `<html><head><title>greet</title></head><body><h1>Hello ${v("name").replace(/[<>"'&]/g, "_")}</h1></body></html>`);
				default:
					return send(404, "text/plain", "nf");
			}
		} catch (err) {
			return send(500, "text/plain", `error: ${err instanceof Error ? err.message : err}`);
		}
	});
}

function listen(server: Server): Promise<number> {
	return new Promise((r) => server.listen(0, "127.0.0.1", () => {
		const a = server.address();
		r(typeof a === "object" && a ? a.port : 0);
	}));
}

async function withApp(fn: (port: number) => Promise<void>): Promise<void> {
	const server = fixtureApp();
	const port = await listen(server);
	try {
		await fn(port);
	} finally {
		server.close();
	}
}

function chromiumAvailable(): boolean {
	try {
		execFileSync(process.env["PLUTO_CHROMIUM_BIN"] ?? "chromium", ["--version"], { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

test("command-injection: pass on vulnerable endpoint, reject on safe", async () => {
	await withApp(async (port) => {
		const pass = await validateCommandInjection({ endpoint: `http://127.0.0.1:${port}/ping`, param: "host", baselineValue: "localhost" });
		assert.equal(pass.passed, true);
		assert.equal(pass.technicalSignal, true);
		assert.equal(pass.impactArtifact, true);

		const reject = await validateCommandInjection({ endpoint: `http://127.0.0.1:${port}/ping-safe`, param: "host", baselineValue: "localhost" });
		assert.equal(reject.passed, false);
	});
});

test("path-traversal: pass on vulnerable endpoint, reject on safe", async () => {
	await withApp(async (port) => {
		const pass = await validatePathTraversal({ endpoint: `http://127.0.0.1:${port}/file`, param: "name", baselineValue: "x" });
		assert.equal(pass.passed, true);

		const reject = await validatePathTraversal({ endpoint: `http://127.0.0.1:${port}/file-safe`, param: "name", baselineValue: "x" });
		assert.equal(reject.passed, false);
	});
});

test("reflected-xss: pass on vulnerable endpoint, reject on safe", async (t) => {
	if (!chromiumAvailable()) {
		t.skip("no chromium binary available");
		return;
	}
	await withApp(async (port) => {
		const pass = await validateXss({ endpoint: `http://127.0.0.1:${port}/greet`, param: "name", baselineValue: "world" });
		assert.equal(pass.passed, true, "vulnerable /greet should confirm XSS execution");

		const reject = await validateXss({ endpoint: `http://127.0.0.1:${port}/greet-safe`, param: "name", baselineValue: "world" });
		assert.equal(reject.passed, false, "safe /greet-safe should not execute the script");
	});
});
