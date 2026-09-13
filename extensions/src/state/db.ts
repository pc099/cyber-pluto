import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { SCHEMA_SQL } from "./schema.js";

const STATE_DIR = "state";
const STATE_DB_FILE = "pluto.db";

/**
 * Opens (creating if absent) the per-engagement SQLite state DB at
 * `<cwd>/state/pluto.db` and applies the Layer 2 schema idempotently.
 * One `DatabaseSync` handle is meant to be shared for the lifetime of a Pi
 * session, not reopened per query.
 */
export function openStateDb(cwd: string): DatabaseSync {
	const path = join(cwd, STATE_DIR, STATE_DB_FILE);
	mkdirSync(dirname(path), { recursive: true });
	const db = new DatabaseSync(path);
	db.exec("PRAGMA foreign_keys = ON;");
	db.exec(SCHEMA_SQL);
	return db;
}
