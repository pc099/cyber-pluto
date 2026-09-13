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
	/**
	 * Active nodes for a target, highest priority first — the "decide next"
	 * half of the Layer 4 loop (Architecture §5.1: default-cred/misconfig
	 * children are seeded above CVE-path children so this ordering surfaces
	 * cheap checks first without the reasoning core needing to be told to
	 * every time). Backed by idx_nodes_target_status.
	 */
	listActiveByTarget(targetId: number): NodeRow[];
	/** The engagement's root node (no parent), if one already exists. */
	findRoot(targetId: number): NodeRow | undefined;
}

export function createNodesRepo(db: DatabaseSync): NodesRepo {
	const insert = db.prepare(
		"INSERT INTO nodes (target_id, parent_id, node_type, status, label, priority) VALUES (?, ?, ?, ?, ?, ?)",
	);
	const selectById = db.prepare("SELECT * FROM nodes WHERE id = ?");
	const selectActiveByTarget = db.prepare(
		"SELECT * FROM nodes WHERE target_id = ? AND status = 'active' ORDER BY priority DESC, created_at ASC",
	);
	const selectRoot = db.prepare(
		"SELECT * FROM nodes WHERE target_id = ? AND parent_id IS NULL ORDER BY id ASC LIMIT 1",
	);

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
		listActiveByTarget(targetId) {
			return selectActiveByTarget.all(targetId) as unknown as NodeRow[];
		},
		findRoot(targetId) {
			return selectRoot.get(targetId) as NodeRow | undefined;
		},
	};
}
