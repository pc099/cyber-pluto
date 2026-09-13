import type { DatabaseSync } from "node:sqlite";
import type { FindingRow, ValidationRow } from "./types.js";

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
	/** Gate 1 rejection — `candidate` to `rejected` when the validator did not
	 * reproduce the effect. Negative results are kept, never deleted. */
	reject(findingId: number): FindingRow;
}

export function createFindingsRepo(db: DatabaseSync): FindingsRepo {
	const insert = db.prepare(
		`INSERT INTO findings
		 (target_id, node_id, port, protocol, service, product, version, honeypot_susp, confidence, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate')`,
	);
	const selectById = db.prepare("SELECT * FROM findings WHERE id = ?");
	const selectValidationById = db.prepare("SELECT * FROM validations WHERE id = ?");
	const updateStatus = db.prepare("UPDATE findings SET status = ? WHERE id = ? AND status = 'candidate'");

	function requireFinding(id: number): FindingRow {
		const finding = selectById.get(id) as unknown as FindingRow | undefined;
		if (!finding) {
			throw new IllegalStatusTransition(`finding ${id} does not exist`);
		}
		return finding;
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
			const { changes } = updateStatus.run("validated", findingId);
			if (changes !== 1) {
				throw new IllegalStatusTransition(`finding ${findingId} was not 'candidate' at promotion time`);
			}
			return requireFinding(findingId);
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
	};
}
