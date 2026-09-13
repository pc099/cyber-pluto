import type { DatabaseSync } from "node:sqlite";
import type { ScreenshotRow, ScreenshotTrigger } from "./types.js";

export interface CreateScreenshotInput {
	targetId: number;
	nodeId?: number | null;
	findingId?: number | null;
	url?: string | null;
	trigger?: ScreenshotTrigger;
	path: string;
	sha256?: string | null;
	width?: number | null;
	height?: number | null;
	note?: string | null;
}

export interface ScreenshotsRepo {
	create(input: CreateScreenshotInput): ScreenshotRow;
	getById(id: number): ScreenshotRow | undefined;
	listByTarget(targetId: number): ScreenshotRow[];
}

export function createScreenshotsRepo(db: DatabaseSync): ScreenshotsRepo {
	const insert = db.prepare(
		`INSERT INTO screenshots (target_id, node_id, finding_id, url, trigger, path, sha256, width, height, note)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	);
	const selectById = db.prepare("SELECT * FROM screenshots WHERE id = ?");
	const selectByTarget = db.prepare("SELECT * FROM screenshots WHERE target_id = ? ORDER BY id DESC");

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.targetId,
				input.nodeId ?? null,
				input.findingId ?? null,
				input.url ?? null,
				input.trigger ?? "manual",
				input.path,
				input.sha256 ?? null,
				input.width ?? null,
				input.height ?? null,
				input.note ?? null,
			);
			return selectById.get(lastInsertRowid) as unknown as ScreenshotRow;
		},
		getById(id) {
			return selectById.get(id) as ScreenshotRow | undefined;
		},
		listByTarget(targetId) {
			return selectByTarget.all(targetId) as unknown as ScreenshotRow[];
		},
	};
}
