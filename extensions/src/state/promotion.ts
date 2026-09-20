/**
 * Gate-1 promotion signatures (board Decision 0001, Item 0).
 *
 * THE PROBLEM: under the sandbox the whole state DB is `pluto`-writable, so a
 * hijacked agent can forge a validated finding with a raw
 * `UPDATE findings SET status='validated' WHERE id=42` — red-lines misses it (a
 * WHERE'd UPDATE trips no rule) and Gate-2 doesn't cover it (a human trusts the
 * provenance stamp). This breaches invariant #1 ("only a deterministic non-LLM
 * validator promotes candidate→validated").
 *
 * THE MECHANISM: every legitimate promotion is signed with an **ed25519 private
 * key held by root, outside `pluto`'s reach** (signing happens in a privileged
 * step — see sandbox/promotion-signer). Consumers verify with the PUBLIC key
 * (readable). A `validated` row whose signature is missing or invalid is treated
 * as TAMPERED — demoted to candidate for trust purposes and flagged. A raw
 * `UPDATE status='validated'` produces no valid signature, so it is inert.
 *
 * SCOPE (honest): this is tamper-EVIDENT against the direct status-flip attack.
 * It is NOT yet tamper-PROOF against a forged `validations` row (that table is
 * also pluto-writable) — closing that requires the validator to run privileged
 * and re-establish the evidence itself. Tracked as the Item-0 follow-on.
 *
 * Pure module: no I/O, no key material. Callers supply keys. Fully unit-testable.
 */
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

/** The exact facts a promotion attests to. Order + separator are the contract;
 * any change is a breaking signature-format change (bump VERSION). */
export interface PromotionClaim {
	findingId: number;
	validationId: number;
	validator: string;
	targetId: number;
	/** A ref/hash tying the promotion to the specific evidence (validations.baseline_ref or an evidence hash). */
	evidenceRef: string;
}

const VERSION = "v1";

/** Canonical, injective serialization of the claim (lengths guard against
 * separator-injection between fields). */
export function canonicalize(c: PromotionClaim): string {
	const parts = [VERSION, String(c.findingId), String(c.validationId), c.validator, String(c.targetId), c.evidenceRef];
	return parts.map((p) => `${p.length}:${p}`).join("|");
}

/** Sign a promotion claim. `privateKey` is an ed25519 key (PEM string or KeyObject) —
 * held ONLY by the privileged signer, never in the agent's reach. Returns base64. */
export function signPromotion(claim: PromotionClaim, privateKey: string | KeyObject): string {
	const key = typeof privateKey === "string" ? createPrivateKey(privateKey) : privateKey;
	return edSign(null, Buffer.from(canonicalize(claim), "utf8"), key).toString("base64");
}

/** Verify a promotion signature with the PUBLIC key (safe to be agent-readable).
 * Returns true only for a signature produced by the matching private key over
 * exactly this claim. Never throws on bad input — returns false. */
export function verifyPromotion(claim: PromotionClaim, signatureB64: string | null | undefined, publicKey: string | KeyObject): boolean {
	if (!signatureB64) return false;
	try {
		const key = typeof publicKey === "string" ? createPublicKey(publicKey) : publicKey;
		return edVerify(null, Buffer.from(canonicalize(claim), "utf8"), key, Buffer.from(signatureB64, "base64"));
	} catch {
		return false;
	}
}
