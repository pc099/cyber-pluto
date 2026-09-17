import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { SCHEMA_SQL } from "./schema.js";

const STATE_DIR = "state";
const STATE_DB_FILE = "pluto.db";

/**
 * The state-DB directory for the current engagement. When the launcher sets
 * `PLUTO_STATE_DIR` (one dir per target, e.g. `engagements/<label>/state`),
 * every extension's DB handle resolves there instead of the shared repo-root
 * `state/`. This stops the specific cross-target corruption we hit: different
 * targets no longer share one `pluto.db` (which accumulated stale-target rows).
 *
 * SCOPE OF THIS ISOLATION (honest): only the **DB** and the lifecycle readout
 * move. The control plane is deliberately GLOBAL — the kill switch and PAUSED
 * file live at repo-root `state/` so `touch state/KILL_SWITCH` halts any run —
 * and the audit `logs/` and `evidence/` still write to the repo root, with
 * evidence filenames keyed on per-DB row ids. So **run one engagement at a
 * time**: concurrent engagements would interleave logs and collide evidence
 * files. Full per-engagement isolation of logs/evidence is the (deferred)
 * multi-engagement feature, not claimed here.
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
