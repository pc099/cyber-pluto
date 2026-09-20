import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { type PromotionClaim, canonicalize, signPromotion, verifyPromotion } from "./promotion.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const claim: PromotionClaim = { findingId: 42, validationId: 7, validator: "idor", targetId: 3, evidenceRef: "evidence/validations/7.json" };

test("a promotion signed by the private key verifies with the public key", () => {
	const sig = signPromotion(claim, privateKey);
	assert.equal(verifyPromotion(claim, sig, publicKey), true);
});

test("an UNSIGNED validated row is rejected (the direct sqlite3 UPDATE forge)", () => {
	// The forge: `UPDATE findings SET status='validated'` sets the string but has NO signature.
	assert.equal(verifyPromotion(claim, null, publicKey), false);
	assert.equal(verifyPromotion(claim, "", publicKey), false);
	assert.equal(verifyPromotion(claim, "not-base64-garbage!!", publicKey), false);
});

test("a signature over a DIFFERENT claim does not validate this one (can't replay/swap)", () => {
	const other = signPromotion({ ...claim, findingId: 99 }, privateKey);
	assert.equal(verifyPromotion(claim, other, publicKey), false, "sig for finding 99 must not validate finding 42");
	const validatorSwap = signPromotion({ ...claim, validator: "sqli" }, privateKey);
	assert.equal(verifyPromotion(claim, validatorSwap, publicKey), false);
});

test("a signature from an ATTACKER key (not the root key) is rejected", () => {
	const attacker = generateKeyPairSync("ed25519");
	const forged = signPromotion(claim, attacker.privateKey);
	assert.equal(verifyPromotion(claim, forged, publicKey), false, "only the real root private key can produce a valid sig");
});

test("canonicalization is injective across field boundaries (no separator injection)", () => {
	const a = canonicalize({ findingId: 1, validationId: 2, validator: "a|b", targetId: 3, evidenceRef: "c" });
	const b = canonicalize({ findingId: 1, validationId: 2, validator: "a", targetId: 3, evidenceRef: "b|c" });
	assert.notEqual(a, b, "different field splits must not collide to the same canonical string");
});
