import type { DatabaseSync } from "node:sqlite";
import type { NodeRow, NodeStatus, NodeType } from "./types.js";

export interface CreateNodeInput {
	targetId: number;
	parentId?: number | null;
	nodeType: NodeType;
	label: string;
	priority?: number;
	status?: NodeStatus;
}

export interface NodesRepo {
	create(input: CreateNodeInput): NodeRow;
	getById(id: number): NodeRow | undefined;
}

export function createNodesRepo(db: DatabaseSync): NodesRepo {
	const insert = db.prepare(
		"INSERT INTO nodes (target_id, parent_id, node_type, status, label, priority) VALUES (?, ?, ?, ?, ?, ?)",
	);
	const selectById = db.prepare("SELECT * FROM nodes WHERE id = ?");

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.targetId,
				input.parentId ?? null,
				input.nodeType,
				input.status ?? "active",
				input.label,
				input.priority ?? 0,
			);
			return selectById.get(lastInsertRowid) as unknown as NodeRow;
		},
		getById(id) {
			return selectById.get(id) as NodeRow | undefined;
		},
	};
}
