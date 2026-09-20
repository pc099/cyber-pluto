/**
 * Resolving the Gate-1 promotion VERIFIER from the environment (Item 0,
 * increment 4) — the consumer side of the signed-promotion mechanism.
 *
 * A verifier checks that a recorded promotion's signature was produced by the
 * root private key over exactly that claim. It reads only the PUBLIC key, which
 * is safe to be agent-readable, so this runs inside pluto's realm.
 *
 *   - PLUTO_PROMOTION_PUBKEY — path to the ed25519 public key. Defaults to
 *     /etc/cyber-pluto/promotion_ed25519.pub (world-readable, installed by
 *     setup.sh). When the key is present, enforcement is ACTIVE: a `validated`
 *     finding whose promotion signature is missing or invalid is treated as
 *     tampered.
 *   - When no public key is configured/readable, no verifier is returned and
 *     enforcement is OFF (dev/tests, or a run predating key setup) — consumers
 *     fall back to trusting the raw status, exactly as before this change.
 */
import { readFileSync } from "node:fs";
import { type KeyObject, createPublicKey } from "node:crypto";
import type { PromotionClaim } from "./promotion.js";
import { verifyPromotion } from "./promotion.js";

const PUBKEY_DEFAULT = "/etc/cyber-pluto/promotion_ed25519.pub";

/** Verify a promotion claim against a signature. Returns true only for a
 * signature the matching root private key produced over exactly this claim. */
export type PromotionVerifier = (claim: PromotionClaim, signatureB64: string | null | undefined) => boolean;

export function resolveVerifier(env: NodeJS.ProcessEnv = process.env): PromotionVerifier | undefined {
	const path = env["PLUTO_PROMOTION_PUBKEY"] ?? PUBKEY_DEFAULT;
	let key: KeyObject;
	try {
		key = createPublicKey(readFileSync(path, "utf8"));
	} catch {
		// No readable public key -> enforcement off (backward compatible).
		return undefined;
	}
	return (claim, sig) => verifyPromotion(claim, sig, key);
}
