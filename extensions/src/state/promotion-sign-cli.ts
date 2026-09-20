#!/usr/bin/env node
/**
 * The PRIVILEGED Gate-1 promotion signer (Item 0, increment 3).
 *
 * Run as ROOT via a root-owned wrapper behind a pinned sudoers rule (see
 * sandbox/), so `pluto` can invoke it but can neither read the private key nor
 * change what runs. It:
 *   1. reads a claim `{ findingId, validationId, ... }` as JSON on stdin;
 *   2. RE-DERIVES the claim from the state DB as root (opened read-only) — the
 *      validator, target, and evidence ref come from the actual `findings` /
 *      `validations` rows, NOT from whatever the caller supplied, so the caller
 *      cannot get a signature over fields that don't match the DB;
 *   3. RE-VERIFIES the gate as root: the finding exists and is still
 *      `candidate`, and the referenced validation exists, belongs to the
 *      finding, and `passed = 1`. promote()'s identical checks run inside
 *      pluto's realm and are only advisory (pluto could skip them); THIS check,
 *      running as root, is the real gate on what gets signed;
 *   4. prints a base64 ed25519 signature to stdout, nothing else.
 *
 * Any failure exits non-zero with a short stderr message and prints no
 * signature, so the calling promote() fails loud rather than recording an
 * unsigned (untrusted) row silently.
 *
 * HONEST SCOPE: the `validations` table is itself pluto-writable, so a hijacked
 * agent can insert a forged `passed` validation row and then obtain a signature
 * for it here. This helper closes the direct `UPDATE status='validated'` flip
 * and the "sign for a finding with no passed validation" gap, but NOT the
 * forged-validation-row path — closing that requires the deterministic
 * validator to RE-RUN here under root (the Item-0 follow-on). Documented, not
 * hidden.
 */
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { stateDbPath } from "./db.js";
import { type PromotionClaim, signPromotion } from "./promotion.js";
import type { FindingRow, ValidationRow } from "./types.js";

function fail(message: string): never {
	process.stderr.write(`promotion-signer: ${message}\n`);
	process.exit(1);
}

function main(): void {
	const keyPath = process.env["PLUTO_PROMOTION_PRIVKEY"];
	if (!keyPath) fail("PLUTO_PROMOTION_PRIVKEY is not set (the root-only private key path)");

	let raw: string;
	try {
		raw = readFileSync(0, "utf8");
	} catch (err) {
		fail(`could not read claim from stdin: ${err instanceof Error ? err.message : String(err)}`);
	}

	let input: unknown;
	try {
		input = JSON.parse(raw);
	} catch {
		fail("stdin is not valid JSON");
	}
	const supplied = input as Partial<PromotionClaim>;
	const findingId = supplied.findingId;
	const validationId = supplied.validationId;
	if (!Number.isInteger(findingId) || !Number.isInteger(validationId)) {
		fail("claim must contain integer findingId and validationId");
	}
	const fid = findingId as number;
	const vid = validationId as number;

	const cwd = process.env["PLUTO_CWD"] ?? process.cwd();
	const db = new DatabaseSync(stateDbPath(cwd), { readOnly: true });
	try {
		const finding = db.prepare("SELECT * FROM findings WHERE id = ?").get(fid) as unknown as
			| FindingRow
			| undefined;
		if (!finding) fail(`finding ${fid} does not exist`);
		if (finding.status !== "candidate") {
			fail(`finding ${fid} is '${finding.status}', not 'candidate' — refusing to sign`);
		}
		const validation = db.prepare("SELECT * FROM validations WHERE id = ?").get(vid) as unknown as
			| ValidationRow
			| undefined;
		if (!validation) fail(`validation ${vid} does not exist`);
		if (validation.finding_id !== fid) {
			fail(`validation ${vid} belongs to finding ${validation.finding_id}, not ${fid}`);
		}
		if (validation.passed !== 1) {
			fail(`validation ${vid} did not pass — refusing to sign`);
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

		const pem = readFileSync(keyPath as string, "utf8");
		process.stdout.write(signPromotion(claim, pem));
	} finally {
		db.close();
	}
}

main();
