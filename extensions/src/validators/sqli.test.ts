/**
 * Gate 1 tests. typescript-patterns requires any change to Gate 1 or the
 * status lifecycle to prove BOTH the pass and the block/reject path. This
 * covers:
 *   - validateSqli reproduces a real SQLi (pass) and does NOT on a safe
 *     control endpoint (reject) — against real in-process HTTP servers;
 *   - the findings-repo status guard promotes only with a passed validation
 *     and refuses every illegal transition (the gate can't be bypassed).
 */
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { openStateDb } from "../state/db.js";
import { createFindingsRepo, IllegalStatusTransition } from "../state/findings-repo.js";
import { createValidationsRepo } from "../state/validations-repo.js";
import { createTargetsRepo } from "../state/targets-repo.js";
import { validateSqli } from "./sqli.js";

/**
 * Hermetic fixture mirroring lab/sqli-demo/app.mjs (vulnerable /item, safe
 * /safe). Kept inline rather than importing the lab app so the test stays
 * self-contained and inside the TS rootDir — the lab app is for the live
 * demo, this fixture is for the gate test.
 */
function createFixtureApp(): Server {
	const db = new DatabaseSync(":memory:");
	db.exec(
		"CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);" +
			"INSERT INTO items (id, name) VALUES (1, 'widget'), (2, 'gadget');",
	);
	return createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		const id = url.searchParams.get("id") ?? "";
		const respond = (rows: unknown, status = 200) => {
			res.writeHead(status, { "content-type": "application/json" });
			res.end(JSON.stringify(rows));
		};
		try {
			if (url.pathname === "/item") {
				respond({ rows: db.prepare(`SELECT id, name FROM items WHERE id = ${id}`).all() });
			} else if (url.pathname === "/safe") {
				respond({ rows: db.prepare("SELECT id, name FROM items WHERE id = ?").all(id) });
			} else {
				respond({ error: "not found" }, 404);
			}
		} catch (err) {
			respond({ error: err instanceof Error ? err.message : String(err) }, 500);
		}
	});
}

function listen(server: Server): Promise<number> {
	return new Promise((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address();
			resolve(typeof addr === "object" && addr ? addr.port : 0);
		});
	});
}

async function withVulnApp(fn: (port: number) => Promise<void>): Promise<void> {
	const server = createFixtureApp();
	const port = await listen(server);
	try {
		await fn(port);
	} finally {
		server.close();
	}
}

test("validateSqli reproduces a real SQL injection (pass path)", async () => {
	await withVulnApp(async (port) => {
		const report = await validateSqli({
			endpoint: `http://127.0.0.1:${port}/item`,
			param: "id",
			baselineValue: "1",
		});
		assert.equal(report.passed, true);
		assert.equal(report.technicalSignal.errorBased, true, "error-based signal expected");
		assert.equal(report.technicalSignal.booleanDifferential, true, "boolean differential expected");
		assert.equal(report.impactArtifact.extracted, true, "marker extraction expected");
		assert.ok(report.impactArtifact.marker, "a marker should be recorded");
		assert.ok(report.baseline.body.length > 0);
		assert.ok(report.attacks.length >= 3);
		// Every verifiable step should have passed on a truly vulnerable target.
		assert.ok(report.steps.every((s) => s.passed), "all verifiable steps should pass");
	});
});

test("validateSqli rejects a safe, parameterized endpoint (reject path)", async () => {
	await withVulnApp(async (port) => {
		const report = await validateSqli({
			endpoint: `http://127.0.0.1:${port}/safe`,
			param: "id",
			baselineValue: "1",
		});
		assert.equal(report.passed, false);
		assert.equal(report.technicalSignal.errorBased, false);
		assert.equal(report.technicalSignal.booleanDifferential, false);
		assert.equal(report.impactArtifact.extracted, false);
	});
});

test("validateSqli reports a network failure as not-passed without throwing", async () => {
	// Nothing is listening on this port.
	const dead = createServer();
	const port = await listen(dead);
	dead.close();
	await new Promise((r) => setTimeout(r, 50));
	const report = await validateSqli({
		endpoint: `http://127.0.0.1:${port}/item`,
		param: "id",
		baselineValue: "1",
	});
	assert.equal(report.passed, false);
	assert.equal(report.steps[0]?.name, "baseline-reachable");
	assert.equal(report.steps[0]?.passed, false);
});

test("findings-repo promotes candidate to validated ONLY with a passed validation", () => {
	const db = openStateDb(`/tmp/pluto-gate-test-${process.pid}-${Date.now()}-a`);
	const targets = createTargetsRepo(db);
	const findings = createFindingsRepo(db);
	const validations = createValidationsRepo(db);
	const target = targets.create({ label: "gate-test" });

	const finding = findings.create({ targetId: target.id, service: "http" });
	assert.equal(finding.status, "candidate");

	const passing = validations.create({
		findingId: finding.id,
		validator: "sqli",
		diffSummary: "reproduced",
		passed: true,
	});
	const promoted = findings.promote(finding.id, passing.id);
	assert.equal(promoted.status, "validated");
	db.close();
});

test("findings-repo status guard refuses every illegal transition", () => {
	const db = openStateDb(`/tmp/pluto-gate-test-${process.pid}-${Date.now()}-b`);
	const targets = createTargetsRepo(db);
	const findings = createFindingsRepo(db);
	const validations = createValidationsRepo(db);
	const target = targets.create({ label: "gate-test" });

	// A candidate cannot be promoted on a FAILED validation.
	const f1 = findings.create({ targetId: target.id, service: "http" });
	const failing = validations.create({
		findingId: f1.id,
		validator: "sqli",
		diffSummary: "not reproduced",
		passed: false,
	});
	assert.throws(() => findings.promote(f1.id, failing.id), IllegalStatusTransition);
	assert.equal(findings.getById(f1.id)?.status, "candidate", "must stay candidate");

	// A validation belonging to another finding cannot promote this one.
	const f2 = findings.create({ targetId: target.id, service: "http" });
	const f3 = findings.create({ targetId: target.id, service: "http" });
	const forF3 = validations.create({ findingId: f3.id, validator: "sqli", diffSummary: "ok", passed: true });
	assert.throws(() => findings.promote(f2.id, forF3.id), IllegalStatusTransition);

	// Already-rejected finding cannot then be promoted or re-rejected.
	const f4 = findings.create({ targetId: target.id, service: "http" });
	findings.reject(f4.id);
	assert.equal(findings.getById(f4.id)?.status, "rejected");
	const forF4 = validations.create({ findingId: f4.id, validator: "sqli", diffSummary: "ok", passed: true });
	assert.throws(() => findings.promote(f4.id, forF4.id), IllegalStatusTransition);

	db.close();
});
