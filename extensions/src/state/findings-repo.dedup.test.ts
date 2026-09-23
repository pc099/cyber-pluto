/**
 * Recon dedup building blocks (Decision 0006). recon re-recorded the same
 * service as a new candidate on every nmap scan; findByPort + enrichFingerprint
 * let it dedup by (target, port, protocol) and upgrade the fingerprint from a
 * richer scan instead of inserting duplicates.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { openStateDb } from "./db.js";
import { createFindingsRepo } from "./findings-repo.js";
import { createTargetsRepo } from "./targets-repo.js";

function db() {
	return openStateDb(`/tmp/pluto-dedup-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

test("findByPort finds an existing service and returns undefined when absent", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const findings = createFindingsRepo(d);
	const t = targets.create({ label: "x" });
	const f = findings.create({ targetId: t.id, port: 81, protocol: "tcp", service: "hosts2-ns" });
	assert.equal(findings.findByPort(t.id, 81, "tcp")?.id, f.id);
	assert.equal(findings.findByPort(t.id, 8080, "tcp"), undefined);
	assert.equal(findings.findByPort(t.id, 81, "udp"), undefined);
});

test("enrichFingerprint upgrades a port-scan guess with a richer -sV fingerprint (no duplicate row)", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const findings = createFindingsRepo(d);
	const t = targets.create({ label: "x" });
	// First scan: bare port scan labels 81 "hosts2-ns", no product.
	const f = findings.create({ targetId: t.id, port: 81, protocol: "tcp", service: "hosts2-ns" });
	// Second scan is richer (-sV): carries a product → wins.
	findings.enrichFingerprint(f.id, { service: "http", product: "nginx", version: "1.18.0" });
	const g = findings.getById(f.id);
	assert.equal(g?.service, "http");
	assert.equal(g?.product, "nginx");
	assert.equal(g?.version, "1.18.0");
	// Still exactly one finding for the port (dedup, not insert).
	assert.equal(findings.listByTarget(t.id).length, 1);
});

test("enrichFingerprint only fills nulls when the new scan is NOT richer (no product)", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const findings = createFindingsRepo(d);
	const t = targets.create({ label: "x" });
	const f = findings.create({ targetId: t.id, port: 80, protocol: "tcp", service: "http", product: "Apache" });
	// A later port-only scan (no product) must NOT clobber the good product.
	findings.enrichFingerprint(f.id, { service: "http", product: null, version: null });
	assert.equal(findings.getById(f.id)?.product, "Apache");
});
