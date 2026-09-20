/**
 * The sanctioned report path (fix for the ungated free-text report bug). The
 * reasoning core once hand-wrote fabricated "engagement complete" files for work
 * it never did. The fix is a DB-grounded generate_report TOOL that refuses to
 * report anything not genuinely validated — there is no sanctioned path to a
 * report for unconfirmed work. This drives the REAL registered tool end-to-end
 * against a live state DB (enforcement off, i.e. no verifier: the ledger-status
 * gate is what's under test here; signature enforcement is covered separately).
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { startEngagement } from "../state/engagement.js";
import cockpitExtension from "./index.js";

type Tool = {
	name: string;
	execute: (id: string, params: Record<string, unknown>, s: unknown, u: unknown, ctx: { cwd: string }) => Promise<{ content: Array<{ text?: string }>; details?: Record<string, unknown> }>;
};

// Capture the tools cockpitExtension registers, ignoring commands/handlers.
const tools = new Map<string, Tool>();
const fakePi = {
	on: () => {},
	registerTool: (t: Tool) => tools.set(t.name, t),
	registerCommand: () => {},
} as unknown as ExtensionAPI;
cockpitExtension(fakePi);

const dir = `/tmp/pluto-genreport-${process.pid}-${Date.now()}`;
process.env["PLUTO_STATE_DIR"] = `${dir}/state`;
process.env["PLUTO_TARGET_LABEL"] = "genreport";
const e = startEngagement(dir); // sets the module singleton the tools read

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
	e.repos.findings.promote(finding.id, v.id); // no verifier configured -> trustworthy

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
