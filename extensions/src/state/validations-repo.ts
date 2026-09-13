import type { DatabaseSync } from "node:sqlite";
import type { ValidationRow } from "./types.js";

export interface CreateValidationInput {
	findingId: number;
	/** Which deterministic strategy ran, e.g. "sqli". */
	validator: string;
	/** Path (repo-relative) to captured baseline evidence. */
	baselineRef?: string | null;
	/** Path (repo-relative) to captured attack evidence. */
	attackRef?: string | null;
	/** The measurable difference observed — must trace to §4.5's technical
	 * signal and/or impact artifact, never a bare "we got a response". */
	diffSummary: string;
	/** true = deterministically reproduced (promote to validated). */
	passed: boolean;
}

export interface ValidationsRepo {
	create(input: CreateValidationInput): ValidationRow;
	getById(id: number): ValidationRow | undefined;
}

export function createValidationsRepo(db: DatabaseSync): ValidationsRepo {
	const insert = db.prepare(
		`INSERT INTO validations (finding_id, validator, baseline_ref, attack_ref, diff_summary, passed)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	);
	const selectById = db.prepare("SELECT * FROM validations WHERE id = ?");

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.findingId,
				input.validator,
				input.baselineRef ?? null,
				input.attackRef ?? null,
				input.diffSummary,
				input.passed ? 1 : 0,
			);
			return selectById.get(lastInsertRowid) as unknown as ValidationRow;
		},
		getById(id) {
			return selectById.get(id) as ValidationRow | undefined;
		},
	};
}
