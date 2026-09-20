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

/** Absolute path to the engagement's SQLite state DB file. Exposed so a
 * privileged out-of-process consumer (the root promotion signer) can open the
 * same DB read-only without going through openStateDb (which applies schema and
 * opens read-write). */
export function stateDbPath(cwd: string): string {
	return join(stateDir(cwd), STATE_DB_FILE);
}

/**
 * The engagement's log directory (audit JSONL, disclosure ledger). Mirrors
 * `stateDir`: when the launcher sets `PLUTO_LOG_DIR` (per-engagement, e.g.
 * `engagements/<label>/logs`) writers land there instead of the repo-root
 * `logs/`. This matters under `--sandbox`: the repo root is bind-mounted
 * READ-ONLY, so a repo-root `logs/` write fails silently and the audit trail is
 * lost — pointing PLUTO_LOG_DIR at the pluto-writable engagement dir keeps
 * "everything is logged" true in confined mode. Defaults to repo-root `logs/`
 * for non-sandbox runs (unchanged behavior).
 */
export function logDir(cwd: string): string {
	return process.env["PLUTO_LOG_DIR"] ?? join(cwd, "logs");
}

/**
 * The engagement's evidence base dir, RELATIVE to cwd — so stored evidence refs
 * (validations.baseline_ref/attack_ref, screenshots.path, attempts output) stay
 * cwd-relative and resolvable by any consumer running with cwd = repo. Honors
 * `PLUTO_EVIDENCE_DIR` (per-engagement, e.g. `engagements/<label>/evidence`);
 * defaults to `evidence`. Same read-only-under-sandbox rationale as logDir: the
 * repo-root `evidence/` is bind-mounted read-only under --sandbox, so writing
 * there fails silently and Gate-1 evidence capture is lost — redirecting to the
 * pluto-writable engagement dir keeps it working in confined mode.
 */
export function evidenceBaseDir(): string {
	return process.env["PLUTO_EVIDENCE_DIR"] ?? "evidence";
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
