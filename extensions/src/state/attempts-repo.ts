import type { DatabaseSync } from "node:sqlite";
import type { AttemptOutcome, AttemptRow } from "./types.js";

export interface StartAttemptInput {
	targetId: number;
	nodeId?: number | null;
	tool: string;
	command: string;
	tactic?: string | null;
	technique?: string | null;
}

export interface FinishAttemptInput {
	outcome: AttemptOutcome;
	outputRef?: string | null;
	reasoningNote?: string | null;
}

export interface AttemptsRepo {
	start(input: StartAttemptInput): AttemptRow;
	finish(id: number, input: FinishAttemptInput): AttemptRow;
	getById(id: number): AttemptRow | undefined;
}

export function createAttemptsRepo(db: DatabaseSync): AttemptsRepo {
	const insert = db.prepare(
		"INSERT INTO attempts (target_id, node_id, tool, command, tactic, technique) VALUES (?, ?, ?, ?, ?, ?)",
	);
	const update = db.prepare(
		`UPDATE attempts
		 SET finished_at = datetime('now'), outcome = ?, output_ref = ?, reasoning_note = ?
		 WHERE id = ?`,
	);
	const selectById = db.prepare("SELECT * FROM attempts WHERE id = ?");

	return {
		start(input) {
			const { lastInsertRowid } = insert.run(
				input.targetId,
				input.nodeId ?? null,
				input.tool,
				input.command,
				input.tactic ?? null,
				input.technique ?? null,
			);
			return selectById.get(lastInsertRowid) as unknown as AttemptRow;
		},
		finish(id, input) {
			update.run(input.outcome, input.outputRef ?? null, input.reasoningNote ?? null, id);
			return selectById.get(id) as unknown as AttemptRow;
		},
		getById(id) {
			return selectById.get(id) as AttemptRow | undefined;
		},
	};
}
