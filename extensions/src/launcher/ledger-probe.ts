#!/usr/bin/env node
/** Prepare SQLite's reader metadata under the confined UID before root signs.
 * Fixed read-only queries only: no journal switch, bootstrap, key or network. */
import assert from "node:assert/strict";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export function probeReadableLedger(ledgerPath: string): void {
	const ledger = lstatSync(ledgerPath);
	if (!isAbsolute(ledgerPath) || realpathSync(ledgerPath) !== ledgerPath || !ledger.isFile() || ledger.nlink !== 1) throw new Error("Ledger probe requires a canonical single-link regular ledger");
	for (const suffix of ["-wal", "-shm", "-journal"]) {
		try {
			const sidecar = lstatSync(`${ledgerPath}${suffix}`);
			if (!sidecar.isFile() || sidecar.isSymbolicLink() || sidecar.nlink !== 1 || sidecar.uid !== ledger.uid) throw new Error("Ledger probe refuses unsafe sidecar");
		} catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
	}
	const database = new DatabaseSync(ledgerPath, { readOnly: true });
	try {
		database.prepare("SELECT id FROM findings LIMIT 1").get();
		database.prepare("SELECT id FROM validations LIMIT 1").get();
	} finally { database.close(); }
}

function main(): void {
	assert.equal(process.env.PLUTO_SANDBOX_MODE, "requested");
	const uid = Number(process.env.PLUTO_READINESS_UID);
	assert.ok(Number.isSafeInteger(uid) && uid > 0);
	assert.equal(process.getuid?.(), uid);
	assert.match(readFileSync("/proc/self/status", "utf8"), /^NoNewPrivs:\s+1$/m);
	assert.equal(process.env.PLUTO_PROMOTION_PRIVKEY, undefined);
	const state = process.env.PLUTO_STATE_DIR;
	assert.ok(state && isAbsolute(state));
	const ledgerPath = join(state, "pluto.db");
	assert.equal(lstatSync(ledgerPath).uid, uid);
	probeReadableLedger(ledgerPath);
}
if (process.argv[1]?.endsWith("/launcher/ledger-probe.js")) {
	try { main(); }
	catch (error) { process.stderr.write(`Confined ledger readiness failed: ${String(error)}\n`); process.exitCode = 1; }
}
