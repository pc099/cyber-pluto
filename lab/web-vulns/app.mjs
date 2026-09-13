/**
 * INTENTIONALLY VULNERABLE local lab target — web vuln classes for the Gate 1
 * validator library (Session 10). 127.0.0.1 only, deliberately insecure by
 * design; NEVER deploy or expose it. Each class has a vulnerable endpoint and
 * a safe control (so the validators can be proven to REJECT as well as pass).
 *
 *   Command injection: /ping?host=       (vuln, shells input)   | /ping-safe
 *   Path traversal:    /file?name=       (vuln, joins raw)      | /file-safe
 *   Reflected XSS:     /greet?name=       (vuln, unescaped)      | /greet-safe
 *
 * Run: node lab/web-vulns/app.mjs [port]   (default 8891)
 */
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, resolve } from "node:path";

const DOCROOT = "/tmp";

function htmlEscape(s) {
	return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

export function createWebVulnApp() {
	return createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		const q = (k) => url.searchParams.get(k) ?? "";
		const send = (status, type, body) => {
			res.writeHead(status, { "content-type": type });
			res.end(body);
		};

		try {
			switch (url.pathname) {
				// --- command injection ---
				case "/ping": {
					// VULNERABLE: user input concatenated into a shell command.
					const out = execSync(`echo pinging ${q("host")}`, { shell: "/bin/bash", timeout: 5000 }).toString();
					return send(200, "text/plain", out);
				}
				case "/ping-safe": {
					// SAFE: no shell; input never reaches a command.
					return send(200, "text/plain", `pinging ${q("host")}\n`);
				}
				// --- path traversal ---
				case "/file": {
					// VULNERABLE: raw join, no normalization/containment.
					const data = readFileSync(join(DOCROOT, q("name")));
					return send(200, "text/plain", data.toString().slice(0, 4000));
				}
				case "/file-safe": {
					// SAFE: resolve and confine to DOCROOT.
					const target = resolve(DOCROOT, q("name"));
					if (!target.startsWith(resolve(DOCROOT) + "/")) return send(400, "text/plain", "denied");
					return send(200, "text/plain", readFileSync(target).toString().slice(0, 4000));
				}
				// --- reflected XSS ---
				case "/greet": {
					// VULNERABLE: reflected unescaped into HTML.
					return send(200, "text/html", `<html><head><title>greet</title></head><body><h1>Hello ${q("name")}</h1></body></html>`);
				}
				case "/greet-safe": {
					// SAFE: HTML-escaped.
					return send(200, "text/html", `<html><head><title>greet</title></head><body><h1>Hello ${htmlEscape(q("name"))}</h1></body></html>`);
				}
				default:
					return send(404, "text/plain", "not found");
			}
		} catch (err) {
			return send(500, "text/plain", `error: ${err && err.message ? err.message : err}`);
		}
	});
}

if (import.meta.url === `file://${process.argv[1]}`) {
	const port = Number(process.argv[2] ?? 8891);
	createWebVulnApp().listen(port, "127.0.0.1", () => {
		console.log(`[web-vulns] INTENTIONALLY VULNERABLE lab app on http://127.0.0.1:${port}`);
		console.log(`[web-vulns]   cmdi:/ping?host=  traversal:/file?name=  xss:/greet?name=  (+ *-safe controls)`);
	});
}
