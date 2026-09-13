/**
 * INTENTIONALLY VULNERABLE local lab target — SQL injection demo.
 *
 * This app exists ONLY so Pluto's Gate 1 SQLi validator (Session 4) has a
 * real injection to deterministically reproduce against. It is deliberately
 * insecure by design. NEVER deploy it, expose it beyond localhost, or copy
 * its query-building pattern into anything real. It binds to 127.0.0.1 only.
 *
 * Endpoints:
 *   GET /item?id=<x>   VULNERABLE: `id` is concatenated straight into the SQL
 *                      (classic error-based + UNION-able + boolean-blind SQLi).
 *   GET /safe?id=<x>   SAFE control: same query via a bound parameter. Used to
 *                      prove the validator correctly REJECTS a non-vulnerable
 *                      endpoint, not just that it confirms a vulnerable one.
 *
 * Run: node lab/sqli-demo/app.mjs [port]   (default 8888)
 */
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";

export function buildDb() {
	const db = new DatabaseSync(":memory:");
	db.exec(`
		CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
		INSERT INTO items (id, name) VALUES (1, 'widget'), (2, 'gadget'), (3, 'gizmo');
		CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
		INSERT INTO users (id, username, password) VALUES (1, 'admin', 's3cr3t-admin-pw');
	`);
	return db;
}

/** Returns an http.Server (not yet listening) so tests can bind an ephemeral
 * port and the CLI entry can bind a fixed one. */
export function createVulnerableApp() {
	const db = buildDb();

	return createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		const id = url.searchParams.get("id") ?? "";

		if (url.pathname === "/item") {
			// VULNERABLE: raw string interpolation of user input into SQL.
			const sql = `SELECT id, name FROM items WHERE id = ${id}`;
			try {
				const rows = db.prepare(sql).all();
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ rows }));
			} catch (err) {
				// Error-based leak: the raw DB error goes back in the response body.
				res.writeHead(500, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: String(err && err.message ? err.message : err) }));
			}
			return;
		}

		if (url.pathname === "/safe") {
			// SAFE: identical query, but `id` is bound, not interpolated.
			try {
				const rows = db.prepare("SELECT id, name FROM items WHERE id = ?").all(id);
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ rows }));
			} catch (err) {
				res.writeHead(500, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: String(err && err.message ? err.message : err) }));
			}
			return;
		}

		res.writeHead(404, { "content-type": "application/json" });
		res.end(JSON.stringify({ error: "not found" }));
	});
}

// CLI entry: `node lab/sqli-demo/app.mjs [port]`
if (import.meta.url === `file://${process.argv[1]}`) {
	const port = Number(process.argv[2] ?? 8888);
	const server = createVulnerableApp();
	server.listen(port, "127.0.0.1", () => {
		console.log(`[sqli-demo] INTENTIONALLY VULNERABLE lab app on http://127.0.0.1:${port}`);
		console.log(`[sqli-demo]   vulnerable: GET /item?id=1     safe control: GET /safe?id=1`);
	});
}
