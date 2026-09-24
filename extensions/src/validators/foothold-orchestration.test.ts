/**
 * Foothold→privesc auto-orchestration (autonomy fix). A validated RCE foothold
 * must seed the privesc checklist into the tree, once, so the harness escalates
 * on its own instead of waiting for the operator to name the vectors.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { openStateDb } from "../state/db.js";
import type { Engagement } from "../state/engagement.js";
import { createFindingsRepo } from "../state/findings-repo.js";
import { createNodesRepo } from "../state/nodes-repo.js";
import { createTargetsRepo } from "../state/targets-repo.js";
import { FOOTHOLD_CLASSES, seedPrivescLeads } from "./foothold-orchestration.js";

function engagementFixture(): Engagement {
	const db = openStateDb(`/tmp/pluto-privesc-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	const targets = createTargetsRepo(db);
	const nodes = createNodesRepo(db);
	const target = targets.create({ label: "x" });
	const root = nodes.create({ targetId: target.id, nodeType: "recon", label: "root" });
	return { db, targetId: target.id, rootNodeId: root.id, repos: { targets, nodes, findings: createFindingsRepo(db) } } as unknown as Engagement;
}

test("a validated foothold seeds the privesc checklist as high-priority tree nodes", () => {
	const e = engagementFixture();
	const before = e.repos.nodes.listByTarget(e.targetId).length;
	const seeded = seedPrivescLeads(e);
	assert.ok(seeded > 0, "should seed at least one lead");
	const nodes = e.repos.nodes.listByTarget(e.targetId);
	assert.ok(nodes.length > before, "tree grew");
	const leads = nodes.filter((n) => n.label.startsWith("[privesc]"));
	assert.ok(leads.length >= 8, `expected the full checklist, got ${leads.length}`);
	// The leads are high-priority and cover the vectors the operator had to name.
	const blob = leads.map((n) => n.label.toLowerCase()).join(" ");
	for (const v of ["sudo -l", "suid", "kernel", "cron", "capabilit", "reuse", "linpeas"]) {
		assert.ok(blob.includes(v), `checklist must cover '${v}'`);
	}
	assert.ok(leads.every((n) => n.priority >= 25), "privesc leads must be high-priority");
});

test("seeding is idempotent — a second validated foothold does not duplicate the checklist", () => {
	const e = engagementFixture();
	assert.ok(seedPrivescLeads(e) > 0);
	const afterFirst = e.repos.nodes.listByTarget(e.targetId).length;
	assert.equal(seedPrivescLeads(e), 0, "second call seeds nothing");
	assert.equal(e.repos.nodes.listByTarget(e.targetId).length, afterFirst, "no duplicate nodes");
});

test("FOOTHOLD_CLASSES covers the RCE validators (not the lesser/non-exec ones)", () => {
	assert.ok(FOOTHOLD_CLASSES.has("file_write_rce"));
	assert.ok(FOOTHOLD_CLASSES.has("command_injection"));
	assert.ok(!FOOTHOLD_CLASSES.has("xss"));
	assert.ok(!FOOTHOLD_CLASSES.has("idor"));
});
