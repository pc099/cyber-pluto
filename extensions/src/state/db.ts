import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { SCHEMA_SQL } from "./schema.js";

const STATE_DIR = "state";
const STATE_DB_FILE = "pluto.db";

/**
 * The state directory for the current engagement. Per-engagement isolation:
 * when the launcher sets `PLUTO_STATE_DIR` (one dir per target, e.g.
 * `engagements/<label>/state`), every extension's DB handle, and the lifecycle
 * control files, resolve there instead of the shared repo-root `state/`. This
 * stops cross-engagement corruption — different targets no longer share one
 * pluto.db (which caused stale-target rows and a false wall-clock stop), and
 * two engagements can run without clobbering each other's ledger.
 */
export function stateDir(cwd: string): string {
	return process.env["PLUTO_STATE_DIR"] ?? join(cwd, STATE_DIR);
}

/**
 * Opens (creating if absent) the engagement's SQLite state DB and applies the
 * Layer 2 schema idempotently.
 *
 * Each extension that needs state opens its own handle to the same file
 * (Pi loads extensions in isolated module realms — see engagement.ts), so
 * `busy_timeout` lets a handle wait briefly instead of failing outright if
 * another handle holds a write lock. WAL keeps readers and the writer from
 * blocking each other.
 */
export function openStateDb(cwd: string): DatabaseSync {
	const path = join(stateDir(cwd), STATE_DB_FILE);
	mkdirSync(dirname(path), { recursive: true });
	const db = new DatabaseSync(path);
	db.exec("PRAGMA foreign_keys = ON;");
	db.exec("PRAGMA busy_timeout = 5000;");
	db.exec("PRAGMA journal_mode = WAL;");
	db.exec(SCHEMA_SQL);
	return db;
}
