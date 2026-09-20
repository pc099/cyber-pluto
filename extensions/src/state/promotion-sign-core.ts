/**
 * The PRIVILEGED signing core (Item 0, increment 3) — the code that actually
 * holds the private key and decides what to sign, run ONLY as root.
 *
 * Given a claim `{ findingId, validationId, ... }` as JSON, it:
 *   1. RE-DERIVES the claim from the state DB as root (opened read-only) — the
 *      validator, target, and evidence ref come from the actual `findings` /
 *      `validations` rows, NOT from whatever the caller supplied, so the caller
 *      cannot obtain a signature over fields that don't match the DB;
 *   2. RE-VERIFIES the gate as root: the finding exists and is still
 *      `candidate`, and the referenced validation exists, belongs to the
 *      finding, and `passed = 1`. promote()'s identical checks run inside
 *      pluto's realm and are only advisory (pluto could skip them); THIS check
 *      is the real gate on what gets signed;
 *   3. returns a base64 ed25519 signature.
 *
 * Throws on any failure so every caller (the one-shot CLI, the socket daemon)
 * fails loud — a promotion whose signature the privileged gate refused must
 * NOT succeed as unsigned.
 *
 * HONEST SCOPE: the `validations` table is itself pluto-writable, so a hijacked
 * agent can insert a forged `passed` validation row and then obtain a signature
 * for it here. This closes the direct `UPDATE status='validated'` flip and the
 * "sign for a finding with no passed validation" gap, but NOT the
 * forged-validation-row path — closing that requires the deterministic
 * validator to RE-RUN here under root (the Item-0 follow-on). Documented, not
 * hidden.
 */
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { stateDbPath } from "./db.js";
import { type PromotionClaim, signPromotion } from "./promotion.js";
import type { FindingRow, ValidationRow } from "./types.js";

export function signClaimAsRoot(rawJson: string, env: NodeJS.ProcessEnv = process.env): string {
	const keyPath = env["PLUTO_PROMOTION_PRIVKEY"];
	if (!keyPath) throw new Error("PLUTO_PROMOTION_PRIVKEY is not set (the root-only private key path)");

	let input: unknown;
	try {
		input = JSON.parse(rawJson);
	} catch {
		throw new Error("claim is not valid JSON");
	}
	const supplied = input as Partial<PromotionClaim>;
	const findingId = supplied.findingId;
	const validationId = supplied.validationId;
	if (!Number.isInteger(findingId) || !Number.isInteger(validationId)) {
		throw new Error("claim must contain integer findingId and validationId");
	}
	const fid = findingId as number;
	const vid = validationId as number;

	const cwd = env["PLUTO_CWD"] ?? process.cwd();
	const db = new DatabaseSync(stateDbPath(cwd), { readOnly: true });
	try {
		const finding = db.prepare("SELECT * FROM findings WHERE id = ?").get(fid) as unknown as FindingRow | undefined;
		if (!finding) throw new Error(`finding ${fid} does not exist`);
		if (finding.status !== "candidate") {
			throw new Error(`finding ${fid} is '${finding.status}', not 'candidate' — refusing to sign`);
		}
		const validation = db.prepare("SELECT * FROM validations WHERE id = ?").get(vid) as unknown as
			| ValidationRow
			| undefined;
		if (!validation) throw new Error(`validation ${vid} does not exist`);
		if (validation.finding_id !== fid) {
			throw new Error(`validation ${vid} belongs to finding ${validation.finding_id}, not ${fid}`);
		}
		if (validation.passed !== 1) {
			throw new Error(`validation ${vid} did not pass — refusing to sign`);
		}

		// Re-derive the claim from the DB rows; ignore any other caller-supplied
		// fields. This is exactly the claim promote() records, so the consumer's
		// verification (increment 4) matches.
		const claim: PromotionClaim = {
			findingId: fid,
			validationId: vid,
			validator: validation.validator,
			targetId: finding.target_id,
			evidenceRef: validation.baseline_ref ?? validation.attack_ref ?? "",
		};
		const pem = readFileSync(keyPath, "utf8");
		return signPromotion(claim, pem);
	} finally {
		db.close();
	}
}
