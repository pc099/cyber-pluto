/**
 * Gate-1 promotion attestation, at the repository layer (Item 0, increment 2).
 *
 * increment 1 (promotion.test.ts) proved the crypto core in isolation. This
 * proves the findings-repo actually RECORDS a signed attestation on promote,
 * that the recorded signature verifies with the public key, and that the
 * backward-compatible unsigned path (no signer configured) still promotes but
 * leaves the attestation unsigned — which a consumer must treat as untrusted.
 *
 * Consumer ENFORCEMENT (demoting an unsigned/invalid `validated` finding) is
 * increment 4; this increment only lays the state plumbing.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { openStateDb } from "./db.js";
import { createFindingsRepo, type PromotionSigner } from "./findings-repo.js";
import { type PromotionClaim, signPromotion, verifyPromotion } from "./promotion.js";
import { createTargetsRepo } from "./targets-repo.js";
import { createValidationsRepo } from "./validations-repo.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

function fixture(signer?: PromotionSigner) {
	const db = openStateDb(`/tmp/pluto-promo-test-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	const targets = createTargetsRepo(db);
	const findings = createFindingsRepo(db, signer ? { signer } : {});
	const validations = createValidationsRepo(db);
	const target = targets.create({ label: "promo-test" });
	const finding = findings.create({ targetId: target.id, service: "http" });
	const validation = validations.create({
		findingId: finding.id,
		validator: "sqli",
		baselineRef: "evidence/validations/baseline-1.json",
		diffSummary: "differential rows returned",
		passed: true,
	});
	return { findings, target, finding, validation };
}

test("promote records a signed attestation that verifies with the public key", () => {
	const signer: PromotionSigner = (claim) => signPromotion(claim, privateKey);
	const { findings, target, finding, validation } = fixture(signer);

	const promoted = findings.promote(finding.id, validation.id);
	assert.equal(promoted.status, "validated");

	const row = findings.getPromotion(finding.id);
	assert.ok(row, "a promotions row must be recorded");
	assert.equal(row.finding_id, finding.id);
	assert.equal(row.validation_id, validation.id);
	assert.equal(row.validator, "sqli");
	assert.equal(row.target_id, target.id);
	assert.equal(row.evidence_ref, "evidence/validations/baseline-1.json");
	assert.ok(row.signature, "the signature must be stored");

	// The stored signature verifies against the reconstructed claim — this is the
	// exact check a consumer runs to trust the `validated` status.
	const claim: PromotionClaim = {
		findingId: row.finding_id,
		validationId: row.validation_id,
		validator: row.validator,
		targetId: row.target_id,
		evidenceRef: row.evidence_ref,
	};
	assert.equal(verifyPromotion(claim, row.signature, publicKey), true);
});

test("a raw status-flip has no signed attestation, so a consumer cannot trust it", () => {
	// Simulate the forge: promote WITHOUT a signer (as a hijacked agent's direct
	// `UPDATE status='validated'` would — no valid signature is ever produced).
	const { findings, finding } = fixture();
	const validation = findings.getPromotion(finding.id);
	assert.equal(validation, undefined, "no promotion yet");

	// The backward-compatible unsigned promotion still flips status...
	findings.promote(finding.id, /* validationId */ 1);
	const row = findings.getPromotion(finding.id);
	assert.ok(row, "an attestation row is still recorded");
	assert.equal(row.signature, null, "but it carries NO signature");

	// ...and an unsigned/absent signature fails verification — the consumer's
	// enforcement (increment 4) will demote such a finding to untrusted.
	const claim: PromotionClaim = {
		findingId: row.finding_id,
		validationId: row.validation_id,
		validator: row.validator,
		targetId: row.target_id,
		evidenceRef: row.evidence_ref,
	};
	assert.equal(verifyPromotion(claim, row.signature, publicKey), false);
});

test("an attacker key does not produce a signature the real public key accepts", () => {
	const attacker = generateKeyPairSync("ed25519");
	const signer: PromotionSigner = (claim) => signPromotion(claim, attacker.privateKey);
	const { findings, finding, validation } = fixture(signer);

	findings.promote(finding.id, validation.id);
	const row = findings.getPromotion(finding.id);
	assert.ok(row?.signature, "attacker still writes a signature...");
	const claim: PromotionClaim = {
		findingId: row.finding_id,
		validationId: row.validation_id,
		validator: row.validator,
		targetId: row.target_id,
		evidenceRef: row.evidence_ref,
	};
	// ...but it does not verify against the ROOT public key.
	assert.equal(verifyPromotion(claim, row.signature, publicKey), false);
});
