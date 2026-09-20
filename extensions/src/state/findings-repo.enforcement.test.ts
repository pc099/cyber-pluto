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

test("enforcement is OFF (backward compatible) when no verifier is configured", () => {
	const d = db();
	const targets = createTargetsRepo(d);
	const findings = createFindingsRepo(d); // no signer, no verifier
	const target = targets.create({ label: "enf" });
	const finding = findings.create({ targetId: target.id, service: "http" });
	d.prepare("UPDATE findings SET status = 'validated' WHERE id = ?").run(finding.id);

	// With no public key to check against, we cannot distrust — the raw status is
	// taken at face value, exactly as before this change.
	assert.equal(findings.isValidatedTrustworthy(finding.id), true);
	assert.deepEqual(findings.listUntrustedValidated(target.id), []);
	assert.equal(findings.markSubmitted(finding.id).status, "submitted");
});
