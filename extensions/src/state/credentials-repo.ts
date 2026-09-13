import type { DatabaseSync } from "node:sqlite";
import type { CredentialRow, SecretType } from "./types.js";

export interface CreateCredentialInput {
	targetId: number;
	nodeId?: number | null;
	username?: string | null;
	secret?: string | null;
	secretType?: SecretType | null;
	source?: string | null;
	scope?: string | null;
	validated?: boolean;
}

export interface CredentialsRepo {
	create(input: CreateCredentialInput): CredentialRow;
	listByTarget(targetId: number): CredentialRow[];
	countByTarget(targetId: number): number;
}

export function createCredentialsRepo(db: DatabaseSync): CredentialsRepo {
	const insert = db.prepare(
		`INSERT INTO credentials (target_id, node_id, username, secret, secret_type, source, scope, validated)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	);
	const selectById = db.prepare("SELECT * FROM credentials WHERE id = ?");
	const selectByTarget = db.prepare("SELECT * FROM credentials WHERE target_id = ? ORDER BY id");
	const countStmt = db.prepare("SELECT COUNT(*) AS c FROM credentials WHERE target_id = ?");

	return {
		create(input) {
			const { lastInsertRowid } = insert.run(
				input.targetId,
				input.nodeId ?? null,
				input.username ?? null,
				input.secret ?? null,
				input.secretType ?? null,
				input.source ?? null,
				input.scope ?? null,
				input.validated ? 1 : 0,
			);
			return selectById.get(lastInsertRowid) as unknown as CredentialRow;
		},
		listByTarget(targetId) {
			return selectByTarget.all(targetId) as unknown as CredentialRow[];
		},
		countByTarget(targetId) {
			return (countStmt.get(targetId) as { c: number }).c;
		},
	};
}
