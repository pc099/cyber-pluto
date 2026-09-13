import type { DatabaseSync } from "node:sqlite";
import type { EngagementPhase, TargetRow } from "./types.js";

export interface CreateTargetInput {
	label: string;
	host?: string | null;
	scopeNotes?: string | null;
	phase?: EngagementPhase;
}

export interface TargetsRepo {
	create(input: CreateTargetInput): TargetRow;
	getById(id: number): TargetRow | undefined;
}

export function createTargetsRepo(db: DatabaseSync): TargetsRepo {
	const insert = db.prepare(
		"INSERT INTO targets (label, host, scope_notes, phase) VALUES (?, ?, ?, ?)",
	);
	const selectById = db.prepare("SELECT * FROM targets WHERE id = ?");

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.label,
				input.host ?? null,
				input.scopeNotes ?? null,
				input.phase ?? "recon",
			);
			return selectById.get(lastInsertRowid) as unknown as TargetRow;
		},
		getById(id) {
			return selectById.get(id) as TargetRow | undefined;
		},
	};
}
