/**
 * The privileged promotion signer (Item 0, increment 3): the env resolver and
 * the real root helper CLI, exercised end-to-end (minus the sudo boundary,
 * which is a system-config concern verified on the box, not in unit tests).
 *
 * The load-bearing property here is that the PRIVILEGED gate is independent of
 * promote()'s in-realm checks: even a caller that hands the helper a claim for a
 * finding with a failing (or missing) validation gets NO signature, and a
 * caller that lies about the validator/evidence gets a signature only over what
 * the DB actually says — never over its fabricated fields.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { openStateDb } from "./db.js";
import { createFindingsRepo } from "./findings-repo.js";
import { type PromotionClaim, verifyPromotion } from "./promotion.js";
import { resolveSigner } from "./promotion-signer.js";
import { createTargetsRepo } from "./targets-repo.js";
import { createValidationsRepo } from "./validations-repo.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const CLI = fileURLToPath(new URL("./promotion-sign-cli.js", import.meta.url));

/** A fresh engagement DB in its own state dir, wired to sign via the REAL root
 * helper CLI (node <cli>), with the private key on disk. Returns everything a
 * test needs plus a cleanup that restores env. */
function privilegedFixture() {
	const dir = mkdtempSync(join(tmpdir(), "pluto-privsign-"));
	const keyFile = join(dir, "promotion_ed25519.key");
	writeFileSync(keyFile, privPem);

	const saved = {
		state: process.env["PLUTO_STATE_DIR"],
		key: process.env["PLUTO_PROMOTION_PRIVKEY"],
		cmd: process.env["PLUTO_PROMOTION_SIGNER_CMD"],
	};
	process.env["PLUTO_STATE_DIR"] = join(dir, "state");
	process.env["PLUTO_PROMOTION_PRIVKEY"] = keyFile;
	process.env["PLUTO_PROMOTION_SIGNER_CMD"] = `${process.execPath} ${CLI}`;

	const db = openStateDb(dir);
	const targets = createTargetsRepo(db);
	const validations = createValidationsRepo(db);
	const findings = createFindingsRepo(db, { signer: resolveSigner() });
	const target = targets.create({ label: "privsign" });

	const restore = () => {
		db.close();
		for (const [k, v] of [
			["PLUTO_STATE_DIR", saved.state],
			["PLUTO_PROMOTION_PRIVKEY", saved.key],
			["PLUTO_PROMOTION_SIGNER_CMD", saved.cmd],
		] as const) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
	};
	return { findings, validations, target, restore };
}

test("resolveSigner returns undefined when no key/command env is set", () => {
	const saved = { key: process.env["PLUTO_PROMOTION_PRIVKEY"], cmd: process.env["PLUTO_PROMOTION_SIGNER_CMD"] };
	delete process.env["PLUTO_PROMOTION_PRIVKEY"];
	delete process.env["PLUTO_PROMOTION_SIGNER_CMD"];
	try {
		assert.equal(resolveSigner(), undefined);
	} finally {
		if (saved.key !== undefined) process.env["PLUTO_PROMOTION_PRIVKEY"] = saved.key;
		if (saved.cmd !== undefined) process.env["PLUTO_PROMOTION_SIGNER_CMD"] = saved.cmd;
	}
});

test("the real privileged CLI signs a legitimate promotion; the signature verifies", () => {
	const { findings, validations, target, restore } = privilegedFixture();
	try {
		const finding = findings.create({ targetId: target.id, service: "http" });
		const validation = validations.create({
			findingId: finding.id,
			validator: "sqli",
			baselineRef: "evidence/validations/baseline.json",
			diffSummary: "rows differ",
			passed: true,
		});

		const promoted = findings.promote(finding.id, validation.id);
		assert.equal(promoted.status, "validated");

		const row = findings.getPromotion(finding.id);
		assert.ok(row?.signature, "the privileged CLI must have produced a signature");
		const claim: PromotionClaim = {
			findingId: row.finding_id,
			validationId: row.validation_id,
			validator: row.validator,
			targetId: row.target_id,
			evidenceRef: row.evidence_ref,
		};
		assert.equal(verifyPromotion(claim, row.signature, publicKey), true);
	} finally {
		restore();
	}
});

test("the privileged gate REFUSES to sign a claim for a failing validation (independent of promote's own check)", () => {
	const { findings, validations, target, restore } = privilegedFixture();
	try {
		const finding = findings.create({ targetId: target.id, service: "http" });
		const failing = validations.create({ findingId: finding.id, validator: "sqli", diffSummary: "no diff", passed: false });

		// Go straight to the signer (as a hijacked in-realm caller would, bypassing
		// promote()'s advisory check). The ROOT gate must still refuse.
		const signer = resolveSigner();
		assert.ok(signer);
		assert.throws(
			() => signer({ findingId: finding.id, validationId: failing.id, validator: "sqli", targetId: target.id, evidenceRef: "x" }),
			/did not pass|refusing to sign|exited/i,
		);
	} finally {
		restore();
	}
});

test("the privileged CLI signs only DB-derived fields, not a caller's fabricated validator/evidence", () => {
	const { findings, validations, target, restore } = privilegedFixture();
	try {
		const finding = findings.create({ targetId: target.id, service: "http" });
		const validation = validations.create({
			findingId: finding.id,
			validator: "idor",
			baselineRef: "evidence/real.json",
			diffSummary: "ok",
			passed: true,
		});
		const signer = resolveSigner();
		assert.ok(signer);

		// Caller lies about validator + evidenceRef; the helper re-derives from DB.
		const sig = signer({ findingId: finding.id, validationId: validation.id, validator: "LIED", targetId: 999, evidenceRef: "FAKE" });

		const dbClaim: PromotionClaim = { findingId: finding.id, validationId: validation.id, validator: "idor", targetId: target.id, evidenceRef: "evidence/real.json" };
		const liedClaim: PromotionClaim = { findingId: finding.id, validationId: validation.id, validator: "LIED", targetId: 999, evidenceRef: "FAKE" };
		assert.equal(verifyPromotion(dbClaim, sig, publicKey), true, "signature is over the DB-derived claim");
		assert.equal(verifyPromotion(liedClaim, sig, publicKey), false, "signature is NOT over the caller's fabricated claim");
	} finally {
		restore();
	}
});
