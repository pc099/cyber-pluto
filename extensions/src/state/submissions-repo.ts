import type { DatabaseSync } from "node:sqlite";
import type { SubmissionRow } from "./types.js";

export interface CreateSubmissionInput {
	findingId: number;
	program?: string | null;
	/** The human who approved this submission — a compliance record (Gate 2). */
	approvedBy: string;
	platformRef?: string | null;
}

export interface SubmissionsRepo {
	/** Records Gate 2 approval. Every submitted finding has one of these,
	 * naming a human approver — the compliance story is true by construction
	 * (Architecture §4.4). Written only from the operator's explicit /approve. */
	create(input: CreateSubmissionInput): SubmissionRow;
	getByFinding(findingId: number): SubmissionRow | undefined;
	listByTarget(targetId: number): SubmissionRow[];
}

export function createSubmissionsRepo(db: DatabaseSync): SubmissionsRepo {
	const insert = db.prepare(
		`INSERT INTO submissions (finding_id, program, approved_by, approved_at, platform_ref)
		 VALUES (?, ?, ?, datetime('now'), ?)`,
	);
	const selectById = db.prepare("SELECT * FROM submissions WHERE id = ?");
	const selectByFinding = db.prepare("SELECT * FROM submissions WHERE finding_id = ? ORDER BY id DESC LIMIT 1");
	const selectByTarget = db.prepare(
		`SELECT s.* FROM submissions s JOIN findings f ON s.finding_id = f.id WHERE f.target_id = ? ORDER BY s.id`,
	);

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.findingId,
				input.program ?? null,
				input.approvedBy,
				input.platformRef ?? null,
			);
			return selectById.get(lastInsertRowid) as unknown as SubmissionRow;
		},
		getByFinding(findingId) {
			return selectByFinding.get(findingId) as SubmissionRow | undefined;
		},
		listByTarget(targetId) {
			return selectByTarget.all(targetId) as unknown as SubmissionRow[];
		},
	};
}
