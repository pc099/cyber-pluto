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
	/** Total attempts recorded for a target — the engagement's tool-call count
	 * for the §10.5 hard cap (persistent across Pi processes). */
	countByTarget(targetId: number): number;
	/** The most recent commands for a target (newest first), for stuck
	 * detection's rolling window (§10.5). */
	recentCommandsByTarget(targetId: number, limit: number): string[];
	/** The most recent full attempt rows for a target (newest first) — the
	 * operator console's audit feed. */
	recentByTarget(targetId: number, limit: number): AttemptRow[];
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
	const countByTargetStmt = db.prepare("SELECT COUNT(*) AS c FROM attempts WHERE target_id = ?");
	const recentByTargetStmt = db.prepare(
		"SELECT command FROM attempts WHERE target_id = ? ORDER BY id DESC LIMIT ?",
	);
	const recentRowsStmt = db.prepare("SELECT * FROM attempts WHERE target_id = ? ORDER BY id DESC LIMIT ?");

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
		countByTarget(targetId) {
			return (countByTargetStmt.get(targetId) as { c: number }).c;
		},
		recentCommandsByTarget(targetId, limit) {
			return (recentByTargetStmt.all(targetId, limit) as Array<{ command: string }>).map((r) => r.command);
		},
		recentByTarget(targetId, limit) {
			return recentRowsStmt.all(targetId, limit) as unknown as AttemptRow[];
		},
	};
}
