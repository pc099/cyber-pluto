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
	/** Gate 2 — `validated` to `submitted`, recorded ONLY after human approval
	 * (a submissions row). Guarded: only a validated finding can be submitted. */
	markSubmitted(findingId: number): FindingRow;
	listByTarget(targetId: number): FindingRow[];
	countByStatus(targetId: number): { candidate: number; validated: number; submitted: number; rejected: number };
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
	const updateSubmitted = db.prepare("UPDATE findings SET status = 'submitted' WHERE id = ? AND status = 'validated'");
	const selectByTarget = db.prepare("SELECT * FROM findings WHERE target_id = ? ORDER BY id");
	const countStatus = db.prepare("SELECT status, COUNT(*) AS c FROM findings WHERE target_id = ? GROUP BY status");

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
		markSubmitted(findingId) {
			const finding = requireFinding(findingId);
			if (finding.status !== "validated") {
				throw new IllegalStatusTransition(
					`finding ${findingId} is '${finding.status}', only a 'validated' finding can be submitted (Gate 2)`,
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
