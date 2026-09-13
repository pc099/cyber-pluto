import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { SCHEMA_SQL } from "./schema.js";

const STATE_DIR = "state";
const STATE_DB_FILE = "pluto.db";

/**
 * Opens (creating if absent) the per-engagement SQLite state DB at
 * `<cwd>/state/pluto.db` and applies the Layer 2 schema idempotently.
 *
 * Each extension that needs state opens its own handle to the same file
 * (Pi loads extensions in isolated module realms — see engagement.ts), so
 * `busy_timeout` lets a handle wait briefly instead of failing outright if
 * another handle holds a write lock. WAL keeps readers and the writer from
 * blocking each other.
 */
export function openStateDb(cwd: string): DatabaseSync {
	const path = join(cwd, STATE_DIR, STATE_DB_FILE);
	mkdirSync(dirname(path), { recursive: true });
	const db = new DatabaseSync(path);
	db.exec("PRAGMA foreign_keys = ON;");
	db.exec("PRAGMA busy_timeout = 5000;");
	db.exec("PRAGMA journal_mode = WAL;");
	db.exec(SCHEMA_SQL);
	return db;
}
