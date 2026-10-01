/**
 * The sanctioned report path (fix for the ungated free-text report bug). The
 * reasoning core once hand-wrote fabricated "engagement complete" files for work
 * it never did. The fix is a DB-grounded generate_report TOOL that refuses to
 * report anything not genuinely validated — there is no sanctioned path to a
 * report for unconfirmed work. This drives the registered tool against an
 * isolated state DB with a fixture signer and verifier, including refusal paths.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { engagementFixture } from "../testing/engagement-fixture.js";
import cockpitExtension from "./index.js";

type Tool = {
	name: string;
	execute: (id: string, params: Record<string, unknown>, s: unknown, u: unknown, ctx: { cwd: string }) => Promise<{ content: Array<{ text?: string }>; details?: Record<string, unknown> }>;
};

// Capture the registered tools and operator approval command.
const tools = new Map<string, Tool>();
const commands = new Map<string, { handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> }>();
const fakePi = {
	on: () => {},
	registerTool: (t: Tool) => tools.set(t.name, t),
	registerCommand: (name: string, command: { handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> }) => commands.set(name, command),
} as unknown as ExtensionAPI;
cockpitExtension(fakePi);

const dir = `/tmp/pluto-genreport-${process.pid}-${Date.now()}`;
const e = engagementFixture(dir, "genreport");

async function run(name: string, params: Record<string, unknown>) {
	const tool = tools.get(name);
	assert.ok(tool, `tool ${name} must be registered`);
	return tool.execute("call-1", params, null, null, { cwd: dir });
}

test("generate_report REFUSES a candidate finding and writes no file", async () => {
	const finding = e.repos.findings.create({ targetId: e.targetId, service: "http" });
	const res = await run("generate_report", { finding_id: finding.id });
	assert.match(res.content[0]?.text ?? "", /Refused/i);
	assert.equal(res.details?.refused, true);
	assert.ok(!existsSync(`${dir}/reports/finding-${finding.id}.md`), "no report file for an unvalidated finding");
});

test("generate_report writes a DB-grounded report for a genuinely validated finding", async () => {
	const finding = e.repos.findings.create({ targetId: e.targetId, service: "http" });
	const v = e.repos.validations.create({ findingId: finding.id, validator: "sqli", baselineRef: "e/b.json", diffSummary: "rows differ", passed: true });
	e.repos.findings.promote(finding.id, v.id);

	const res = await run("generate_report", { finding_id: finding.id });
	const path = `${dir}/reports/finding-${finding.id}.md`;
	assert.ok(existsSync(path), "report file must be written");
	const md = readFileSync(path, "utf8");
	assert.match(md, /Validation \(Gate 1/); // built from the real validation record
	assert.doesNotMatch(md, /UNVERIFIED|DO NOT SUBMIT/i); // it's genuine
	assert.match(res.content[0]?.text ?? "", /Gate 2/); // reminds that human approval is still required
});

test("list_findings reports the ledger counts, not the model's narrative", async () => {
	const res = await run("list_findings", {});
	assert.match(res.content[0]?.text ?? "", /Ledger: validated \d+ · candidate \d+/);
});

test("human approval is atomic after UI waits and rejected changes leave no approval row", async () => {
	for (const mutate of [false, true]) {
		const finding = e.repos.findings.create({ targetId: e.targetId });
		const validation = e.repos.validations.create({ findingId: finding.id, validator: "fixture", diffSummary: "fixture", passed: true });
		e.repos.findings.promote(finding.id, validation.id);
		let confirmations = 0;
		const ctx = {
			cwd: dir,
			ui: {
				confirm: async () => {
					confirmations++;
					if (mutate) e.db.prepare("UPDATE findings SET status = 'rejected' WHERE id = ?").run(finding.id);
					return true;
				},
				input: async () => "fixture-operator",
				notify: () => {}, setWidget: () => {},
			},
		} as unknown as ExtensionCommandContext;
		await commands.get("approve")!.handler(String(finding.id), ctx);
		assert.equal(confirmations, 1);
		const rows = e.db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE finding_id = ?").get(finding.id) as { n: number };
		assert.equal(rows.n, mutate ? 0 : 1);
		assert.equal(e.repos.findings.getById(finding.id)?.status, mutate ? "rejected" : "submitted");
	}
});

test("unsigned reproduction cannot generate a trusted report or approval record", async () => {
	const finding = e.repos.findings.create({ targetId: e.targetId });
	const validation = e.repos.validations.create({ findingId: finding.id, validator: "fixture", diffSummary: "fixture", passed: true });
	e.repos.findings.promote(finding.id, validation.id);
	e.db.prepare("UPDATE promotions SET signature = NULL WHERE finding_id = ?").run(finding.id);
	const result = await run("generate_report", { finding_id: finding.id });
	assert.equal(result.details?.refused, true);
	assert.equal(existsSync(`${dir}/reports/finding-${finding.id}.md`), false);
	let confirms = 0;
	const ctx = { cwd: dir, ui: { notify: () => {}, confirm: async () => { confirms++; return true; } } } as unknown as ExtensionCommandContext;
	await commands.get("approve")!.handler(String(finding.id), ctx);
	assert.equal(confirms, 0);
	const rows = e.db.prepare("SELECT COUNT(*) AS n FROM submissions WHERE finding_id = ?").get(finding.id) as { n: number };
	assert.equal(rows.n, 0);
});
