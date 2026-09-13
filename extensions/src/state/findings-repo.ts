import type { DatabaseSync } from "node:sqlite";
import type { FindingRow } from "./types.js";

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

export interface FindingsRepo {
	/**
	 * Every finding is born `candidate` (pluto-build invariant 3) — a
	 * version-string fingerprint is not evidence on its own (backporting
	 * makes it unreliable), so there is deliberately no way to construct a
	 * finding at any other status here. Promotion to `validated` is Gate 1's
	 * job (Architecture §4.4, Session 4) and lives in its own repository
	 * method once that validator exists.
	 */
	create(input: CreateFindingInput): FindingRow;
	getById(id: number): FindingRow | undefined;
}

export function createFindingsRepo(db: DatabaseSync): FindingsRepo {
	const insert = db.prepare(
		`INSERT INTO findings
		 (target_id, node_id, port, protocol, service, product, version, honeypot_susp, confidence, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate')`,
	);
	const selectById = db.prepare("SELECT * FROM findings WHERE id = ?");

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
	};
}
