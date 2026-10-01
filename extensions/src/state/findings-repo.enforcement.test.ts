/**
 * Gate-1 consumer ENFORCEMENT (Item 0, increment 4) — the increment that makes
 * the signed-promotion mechanism load-bearing. Proves BOTH paths (per
 * typescript-patterns): a genuinely signed 'validated' finding submits; a forged
 * one (validated in the pluto-writable DB with no valid signature) is refused at
 * the Gate-2 boundary and reported as untrusted. Also proves enforcement is OFF
 * (backward compatible) when no public key is configured.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { openStateDb } from "./db.js";
import { IllegalStatusTransition, createFindingsRepo } from "./findings-repo.js";
import { type PromotionClaim, signPromotion, verifyPromotion } from "./promotion.js";
import type { PromotionVerifier } from "./promotion-verifier.js";
import { createTargetsRepo } from "./targets-repo.js";
import { createValidationsRepo } from "./validations-repo.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const verifier: PromotionVerifier = (claim, sig) => verifyPromotion(claim, sig, publicKey);
const goodSigner = (claim: PromotionClaim) => signPromotion(claim, privateKey);

function db() {
	return openStateDb(`/tmp/pluto-enforce-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

test("a genuinely signed 'validated' finding is trustworthy and can be submitted (Gate 2)", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const validations = createValidationsRepo(d);
	const findings = createFindingsRepo(d, { signer: goodSigner, verifier });
	const target = targets.create({ label: "enf" });
	const finding = findings.create({ targetId: target.id, service: "http" });
	const v = validations.create({ findingId: finding.id, validator: "sqli", baselineRef: "e/b.json", diffSummary: "d", passed: true });

	findings.promote(finding.id, v.id);
	assert.equal(findings.isValidatedTrustworthy(finding.id), true);
	assert.deepEqual(findings.listUntrustedValidated(target.id), []);
	const submitted = findings.markSubmitted(finding.id);
	assert.equal(submitted.status, "submitted");
});

test("a forged 'validated' finding (raw status-flip) is untrusted and REFUSED at Gate 2", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const findings = createFindingsRepo(d, { verifier }); // verifier on, but NO signer
	const target = targets.create({ label: "enf" });
	const finding = findings.create({ targetId: target.id, service: "http" });

	// Simulate the forge exactly: a raw UPDATE flips status with no signed
	// promotion (what `sqlite3 "UPDATE findings SET status='validated'"` does).
	d.prepare("UPDATE findings SET status = 'validated' WHERE id = ?").run(finding.id);
	assert.equal(findings.getById(finding.id)?.status, "validated");

	// Enforcement sees through it.
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	assert.deepEqual(
		findings.listUntrustedValidated(target.id).map((f) => f.id),
		[finding.id],
	);
	// Gate 2 refuses to submit it.
	assert.throws(() => findings.markSubmitted(finding.id), (err) => {
		assert.ok(err instanceof IllegalStatusTransition);
		assert.match(err.message, /missing or invalid|possible tampering/i);
		return true;
	});
});

test("a promotion row carrying an ATTACKER signature is also refused at Gate 2", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const validations = createValidationsRepo(d);
	const attacker = generateKeyPairSync("ed25519");
	// The agent signs its own promotion with a key it controls (not root's).
	const findings = createFindingsRepo(d, { signer: (c) => signPromotion(c, attacker.privateKey), verifier });
	const target = targets.create({ label: "enf" });
	const finding = findings.create({ targetId: target.id, service: "http" });
	const v = validations.create({ findingId: finding.id, validator: "sqli", diffSummary: "d", passed: true });

	findings.promote(finding.id, v.id); // records an attacker-signed row
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	assert.throws(() => findings.markSubmitted(finding.id), IllegalStatusTransition);
});

test("missing verification refuses Gate 2 and never establishes a current fact", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const findings = createFindingsRepo(d); // no signer, no verifier
	const target = targets.create({ label: "enf" });
	const finding = findings.create({ targetId: target.id, service: "http" });
	d.prepare("UPDATE findings SET status = 'validated' WHERE id = ?").run(finding.id);

	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	assert.deepEqual(findings.listUntrustedValidated(target.id).map((f) => f.id), [finding.id]);
	assert.throws(() => findings.markSubmitted(finding.id), IllegalStatusTransition);
});

test("milestones require current status, verified signature and matching passed associations", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const validations = createValidationsRepo(d);
	const findings = createFindingsRepo(d, { signer: goodSigner, verifier });
	const target = targets.create({ label: "current" });
	const other = targets.create({ label: "other" });
	const finding = findings.create({ targetId: target.id });
	const v = validations.create({ findingId: finding.id, validator: "privilege_escalation", baselineRef: "e/b", diffSummary: "fixture", passed: true });
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	findings.promote(finding.id, v.id);
	assert.equal(findings.hasValidatedFootholdClass(target.id, ["privilege_escalation"]), true);
	assert.equal(findings.hasValidatedFootholdClass(other.id, ["privilege_escalation"]), false);
	findings.markSubmitted(finding.id);
	assert.equal(findings.isValidatedTrustworthy(finding.id), true);
	assert.equal(findings.hasValidatedFootholdClass(target.id, ["privilege_escalation"]), true);
	for (const status of ["candidate", "rejected"]) {
		d.prepare("UPDATE findings SET status = ? WHERE id = ?").run(status, finding.id);
		assert.equal(findings.isValidatedTrustworthy(finding.id), false);
		assert.equal(findings.hasValidatedFootholdClass(target.id, ["privilege_escalation"]), false);
	}
	d.prepare("UPDATE findings SET status = 'validated' WHERE id = ?").run(finding.id);
	d.prepare("UPDATE validations SET passed = 0 WHERE id = ?").run(v.id);
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	d.prepare("UPDATE validations SET passed = 1, validator = 'different' WHERE id = ?").run(v.id);
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	d.prepare("UPDATE validations SET validator = 'privilege_escalation', baseline_ref = 'changed' WHERE id = ?").run(v.id);
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	d.prepare("UPDATE validations SET baseline_ref = 'e/b' WHERE id = ?").run(v.id);
	d.prepare("UPDATE findings SET target_id = ? WHERE id = ?").run(other.id, finding.id);
	assert.equal(findings.isValidatedTrustworthy(finding.id), false);
	d.close();
});

test("unsigned promotions and signed rows without a verifier cannot establish milestones", () => {
	for (const opts of [{ verifier }, { signer: goodSigner }]) {
		const d = db();
		const targets = createTargetsRepo(d);
		const validations = createValidationsRepo(d);
		const findings = createFindingsRepo(d, opts);
		const target = targets.create({ label: "diagnostic" });
		const finding = findings.create({ targetId: target.id });
		const v = validations.create({ findingId: finding.id, validator: "privilege_escalation", diffSummary: "fixture", passed: true });
		findings.promote(finding.id, v.id);
		assert.equal(findings.isValidatedTrustworthy(finding.id), false);
		assert.equal(findings.hasValidatedFootholdClass(target.id, ["privilege_escalation"]), false);
		assert.throws(() => findings.markSubmitted(finding.id), IllegalStatusTransition);
		d.close();
	}
});
