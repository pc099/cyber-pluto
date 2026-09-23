import type { DatabaseSync } from "node:sqlite";
import type { PromotionClaim } from "./promotion.js";
import type { PromotionVerifier } from "./promotion-verifier.js";
import type { FindingRow, ValidationRow } from "./types.js";

/**
 * A privileged signer for a Gate-1 promotion claim. Returns a base64 signature,
 * or null when signing is unavailable. It is injected (not called in-process)
 * so the private key never sits in the agent's realm: in the sandbox this shells
 * to the root-held signer (Item-0 increment 3); in a trusted single-operator run
 * root can sign directly; in dev/tests it may be absent, and promotions are then
 * recorded UNSIGNED (an unsigned `validated` finding is untrusted by consumers).
 */
export type PromotionSigner = (claim: PromotionClaim) => string | null;

/** A recorded Gate-1 promotion attestation (the `promotions` table). The claim
 * fields are the exact facts the signature covers; `signature` is null when the
 * promotion was recorded without a signer configured. */
export interface PromotionRow {
	id: number;
	finding_id: number;
	validation_id: number;
	validator: string;
	target_id: number;
	evidence_ref: string;
	signature: string | null;
	created_at: string;
}

export interface CreateFindingInput {
	targetId: number;
	nodeId?: number | null;
	port?: number | null;
	protocol?: "tcp" | "udp" | null;
	service?: string | null;
	product?: string | null;
	version?: string | null;
	honeypotSuspected?: boolean;
	confidence?: number | null;
}

/**
 * Thrown when code attempts a status transition the two-gate model forbids —
 * e.g. promoting a finding that has no passed validation, or one that isn't
 * currently `candidate`. This is a genuine invariant violation (an attempt to
 * bypass Gate 1), not an expected outcome, so it throws rather than returning
 * a Result: the gate should fail loud, never silently no-op.
 */
export class IllegalStatusTransition extends Error {
	constructor(message: string) {
		super(message);
		this.name = "IllegalStatusTransition";
	}
}

export interface FindingsRepo {
	/**
	 * Every finding is born `candidate` (pluto-build invariant 3) — a
	 * version-string fingerprint is not evidence on its own (backporting
	 * makes it unreliable), so there is deliberately no way to construct a
	 * finding at any other status here.
	 */
	create(input: CreateFindingInput): FindingRow;
	getById(id: number): FindingRow | undefined;
	/** The existing finding for a (target, port, protocol), if any — so recon can
	 * DEDUP: re-recording the same service on every nmap scan produced duplicate
	 * candidates (a `-p-` scan even labels a port differently than `-sV`). */
	findByPort(targetId: number, port: number, protocol: string): FindingRow | undefined;
	/** Fill in / upgrade a fingerprint from a richer scan (a `-sV` scan carrying a
	 * product wins; otherwise only null fields are filled). Never creates a row. */
	enrichFingerprint(id: number, patch: { service?: string | null; product?: string | null; version?: string | null }): void;
	/**
	 * Gate 1 promotion — the ONLY path from `candidate` to `validated`
	 * (Architecture §4.4). Enforced here, in one place, so no other code can
	 * fabricate a validated finding:
	 *   - the finding must currently be `candidate`;
	 *   - the referenced `validations` row must exist, belong to this finding,
	 *     and have `passed = 1`.
	 * Anything else throws IllegalStatusTransition. The reasoning core cannot
	 * reach this without a deterministic validator having produced a passed
	 * validation row first.
	 */
	promote(findingId: number, validationId: number): FindingRow;
	/** The operative (latest) Gate-1 promotion attestation for a finding, or
	 * undefined if it was never promoted through this path. Consumers verify its
	 * `signature` against the public key to decide whether a `validated` status
	 * is trustworthy (Item-0 increment 4). */
	getPromotion(findingId: number): PromotionRow | undefined;
	/**
	 * Gate-1 enforcement (Item-0 increment 4): is this finding's `validated`
	 * status backed by a promotion signature the root public key accepts?
	 *   - not `validated` -> true (nothing to distrust);
	 *   - no verifier configured (no readable public key) -> true (enforcement
	 *     off; backward compatible, e.g. dev/tests);
	 *   - `validated` with a verifier -> true ONLY if the recorded promotion's
	 *     signature verifies against the reconstructed claim. A missing row, an
	 *     unsigned row (the raw `UPDATE status='validated'` forge), or an invalid
	 *     signature -> false.
	 */
	isValidatedTrustworthy(findingId: number): boolean;
	/** Validated findings that FAIL signature verification — for the operator
	 * readout (cockpit/report/lifecycle) to flag possible tampering. Empty when
	 * no verifier is configured. */
	listUntrustedValidated(targetId: number): FindingRow[];
	/** Gate 1 rejection — `candidate` to `rejected` when the validator did not
	 * reproduce the effect. Negative results are kept, never deleted. */
	reject(findingId: number): FindingRow;
	/** Gate 2 — `validated` to `submitted`, recorded ONLY after human approval
	 * (a submissions row). Guarded: only a validated finding can be submitted. */
	markSubmitted(findingId: number): FindingRow;
	listByTarget(targetId: number): FindingRow[];
	countByStatus(targetId: number): { candidate: number; validated: number; submitted: number; rejected: number };
}

export interface FindingsRepoOptions {
	/** Injected privileged signer for Gate-1 promotions. When absent, promotions
	 * are recorded UNSIGNED (backward-compatible; non-sandbox dev/tests). */
	signer?: PromotionSigner;
	/** Injected verifier (public key) for consumer enforcement. When absent,
	 * enforcement is OFF and a `validated` status is trusted as-is (backward
	 * compatible). When present, an unsigned/invalid `validated` finding cannot be
	 * submitted and is reported as untrusted. */
	verifier?: PromotionVerifier;
}

export function createFindingsRepo(db: DatabaseSync, opts: FindingsRepoOptions = {}): FindingsRepo {
	const insert = db.prepare(
		`INSERT INTO findings
		 (target_id, node_id, port, protocol, service, product, version, honeypot_susp, confidence, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate')`,
	);
	const selectById = db.prepare("SELECT * FROM findings WHERE id = ?");
	const selectByPort = db.prepare("SELECT * FROM findings WHERE target_id = ? AND port = ? AND protocol = ? ORDER BY id LIMIT 1");
	const enrichStmt = db.prepare("UPDATE findings SET service = ?, product = ?, version = ? WHERE id = ?");
	const selectValidationById = db.prepare("SELECT * FROM validations WHERE id = ?");
	const updateStatus = db.prepare("UPDATE findings SET status = ? WHERE id = ? AND status = 'candidate'");
	const updateSubmitted = db.prepare("UPDATE findings SET status = 'submitted' WHERE id = ? AND status = 'validated'");
	const selectByTarget = db.prepare("SELECT * FROM findings WHERE target_id = ? ORDER BY id");
	const countStatus = db.prepare("SELECT status, COUNT(*) AS c FROM findings WHERE target_id = ? GROUP BY status");
	const insertPromotion = db.prepare(
		`INSERT INTO promotions (finding_id, validation_id, validator, target_id, evidence_ref, signature)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	);
	const selectPromotion = db.prepare(
		"SELECT * FROM promotions WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
	);

	function requireFinding(id: number): FindingRow {
		const finding = selectById.get(id) as unknown as FindingRow | undefined;
		if (!finding) {
			throw new IllegalStatusTransition(`finding ${id} does not exist`);
		}
		return finding;
	}

	/** Core enforcement predicate shared by isValidatedTrustworthy(),
	 * markSubmitted(), and listUntrustedValidated(). See the interface docstring
	 * for the trust rules. */
	function validatedIsTrustworthy(finding: FindingRow): boolean {
		if (finding.status !== "validated") return true;
		if (!opts.verifier) return true; // enforcement off (no public key)
		const row = selectPromotion.get(finding.id) as PromotionRow | undefined;
		if (!row) return false; // validated with no attestation at all (a raw status-flip)
		const claim: PromotionClaim = {
			findingId: row.finding_id,
			validationId: row.validation_id,
			validator: row.validator,
			targetId: row.target_id,
			evidenceRef: row.evidence_ref,
		};
		return opts.verifier(claim, row.signature);
	}

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.targetId,
				input.nodeId ?? null,
				input.port ?? null,
				input.protocol ?? null,
				input.service ?? null,
				input.product ?? null,
				input.version ?? null,
				input.honeypotSuspected ? 1 : 0,
				input.confidence ?? null,
			);
			return selectById.get(lastInsertRowid) as unknown as FindingRow;
		},
		getById(id) {
			return selectById.get(id) as FindingRow | undefined;
		},
		findByPort(targetId, port, protocol) {
			return selectByPort.get(targetId, port, protocol) as FindingRow | undefined;
		},
		enrichFingerprint(id, patch) {
			const f = requireFinding(id);
			const richer = patch.product != null && patch.product !== ""; // a -sV scan carries product
			const service = richer ? (patch.service ?? f.service) : (f.service ?? patch.service ?? null);
			const product = patch.product ?? f.product;
			const version = patch.version ?? f.version;
			enrichStmt.run(service, product, version, id);
		},
		promote(findingId, validationId) {
			const finding = requireFinding(findingId);
			if (finding.status !== "candidate") {
				throw new IllegalStatusTransition(
					`finding ${findingId} is '${finding.status}', only 'candidate' can be promoted to 'validated'`,
				);
			}
			const validation = selectValidationById.get(validationId) as unknown as ValidationRow | undefined;
			if (!validation) {
				throw new IllegalStatusTransition(`validation ${validationId} does not exist`);
			}
			if (validation.finding_id !== findingId) {
				throw new IllegalStatusTransition(
					`validation ${validationId} belongs to finding ${validation.finding_id}, not ${findingId}`,
				);
			}
			if (validation.passed !== 1) {
				throw new IllegalStatusTransition(
					`validation ${validationId} did not pass; cannot promote finding ${findingId} to 'validated'`,
				);
			}
			// Build and sign the attestation BEFORE flipping status: a signer fault
			// must never leave a finding `validated` with no (or an unsigned)
			// promotions row, which a consumer would read as tampering. The claim
			// covers exactly the facts a consumer must trust; the signature (when a
			// signer is configured) is what a raw `UPDATE status='validated'` cannot
			// forge.
			const claim: PromotionClaim = {
				findingId,
				validationId,
				validator: validation.validator,
				targetId: finding.target_id,
				evidenceRef: validation.baseline_ref ?? validation.attack_ref ?? "",
			};
			let signature: string | null = null;
			try {
				signature = opts.signer ? opts.signer(claim) : null;
			} catch (err) {
				throw new IllegalStatusTransition(
					`promotion signer failed for finding ${findingId}: ${err instanceof Error ? err.message : String(err)}`,
				);
			}
			// Flip status and record the attestation atomically, so the two never
			// diverge on a mid-write fault.
			db.exec("BEGIN");
			try {
				const { changes } = updateStatus.run("validated", findingId);
				if (changes !== 1) {
					throw new IllegalStatusTransition(`finding ${findingId} was not 'candidate' at promotion time`);
				}
				insertPromotion.run(findingId, validationId, claim.validator, claim.targetId, claim.evidenceRef, signature);
				db.exec("COMMIT");
			} catch (err) {
				db.exec("ROLLBACK");
				throw err;
			}
			return requireFinding(findingId);
		},
		getPromotion(findingId) {
			return selectPromotion.get(findingId) as PromotionRow | undefined;
		},
		isValidatedTrustworthy(findingId) {
			return validatedIsTrustworthy(requireFinding(findingId));
		},
		listUntrustedValidated(targetId) {
			if (!opts.verifier) return [];
			return (selectByTarget.all(targetId) as unknown as FindingRow[]).filter(
				(f) => f.status === "validated" && !validatedIsTrustworthy(f),
			);
		},
		reject(findingId) {
			const finding = requireFinding(findingId);
			if (finding.status !== "candidate") {
				throw new IllegalStatusTransition(
					`finding ${findingId} is '${finding.status}', only 'candidate' can be rejected`,
				);
			}
			updateStatus.run("rejected", findingId);
			return requireFinding(findingId);
		},
		markSubmitted(findingId) {
			const finding = requireFinding(findingId);
			if (finding.status !== "validated") {
				throw new IllegalStatusTransition(
					`finding ${findingId} is '${finding.status}', only a 'validated' finding can be submitted (Gate 2)`,
				);
			}
			// Gate-1 enforcement at the Gate-2 boundary: a finding can read as
			// 'validated' in the pluto-writable DB without a real promotion (a raw
			// status-flip forge). When a verifier is configured, refuse to submit
			// one whose promotion signature the root public key does not accept —
			// this is where the signed-promotion mechanism becomes load-bearing.
			if (!validatedIsTrustworthy(finding)) {
				throw new IllegalStatusTransition(
					`finding ${findingId} is 'validated' but its Gate-1 promotion signature is missing or invalid — refusing to submit (possible tampering)`,
				);
			}
			const { changes } = updateSubmitted.run(findingId);
			if (changes !== 1) {
				throw new IllegalStatusTransition(`finding ${findingId} was not 'validated' at submission time`);
			}
			return requireFinding(findingId);
		},
		listByTarget(targetId) {
			return selectByTarget.all(targetId) as unknown as FindingRow[];
		},
		countByStatus(targetId) {
			const counts = { candidate: 0, validated: 0, submitted: 0, rejected: 0 };
			for (const row of countStatus.all(targetId) as Array<{ status: string; c: number }>) {
				if (row.status in counts) counts[row.status as keyof typeof counts] = row.c;
			}
			return counts;
		},
	};
}
