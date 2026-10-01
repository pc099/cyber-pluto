/**
 * Report integrity (Item-0 enforcement at the report consumer). A finding can
 * read 'validated' in the pluto-writable DB without a valid Gate-1 promotion
 * signature (a forge). The report must lead with a prominent TAMPER warning for
 * such a finding, and must NOT for a genuine one — so a forged finding is never
 * dressed up as a submission-ready report.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { CredentialRow, FindingRow, TargetRow, ValidationRow } from "../state/types.js";
import { buildFindingReport } from "./report.js";

const target: TargetRow = {
	id: 1,
	label: "t",
	host: "10.0.0.5",
	scope_notes: null,
	phase: "recon",
	created_at: "now",
} as unknown as TargetRow;

const validated: FindingRow = {
	id: 7,
	target_id: 1,
	status: "validated",
	service: "http",
	product: null,
	version: null,
	port: 80,
	protocol: "tcp",
	confidence: null,
} as unknown as FindingRow;

const passedValidation: ValidationRow = {
	id: 3,
	finding_id: 7,
	validator: "sqli",
	baseline_ref: "evidence/b.json",
	attack_ref: "evidence/a.json",
	diff_summary: "rows differ",
	passed: 1,
	validated_at: "now",
};

const creds: CredentialRow[] = [];

test("an UNVERIFIED validated finding's report leads with a DO NOT SUBMIT tamper warning", () => {
	const md = buildFindingReport({ finding: validated, target, validations: [passedValidation], credentials: creds, trustworthy: false });
	assert.match(md, /UNVERIFIED/);
	assert.match(md, /DO NOT SUBMIT/i);
	// The warning must appear before the validation section, not be buried.
	assert.ok(md.indexOf("DO NOT SUBMIT") < md.indexOf("## Validation"), "warning must precede the validation section");
});

test("a genuine (trustworthy) validated finding's report carries no tamper warning", () => {
	const md = buildFindingReport({ finding: validated, target, validations: [passedValidation], credentials: creds, trustworthy: true });
	assert.doesNotMatch(md, /UNVERIFIED|DO NOT SUBMIT/i);
	assert.match(md, /Validation \(Gate 1/);
});

test("missing explicit verification produces a diagnostic report", () => {
	const md = buildFindingReport({ finding: validated, target, validations: [passedValidation], credentials: creds });
	assert.match(md, /UNVERIFIED|DO NOT SUBMIT/i);
});
