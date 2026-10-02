import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { SCHEMA_SQL } from "../state/schema.js";
import { probeReadableLedger } from "./ledger-probe.js";

test("read-only ledger readiness preserves DELETE mode and ledger bytes without bootstrapping rows", () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-ledger-probe-"));
	try {
		const path = join(root, "pluto.db");
		const database = new DatabaseSync(path);
		try { database.exec(SCHEMA_SQL); } finally { database.close(); }
		const before = readFileSync(path);
		probeReadableLedger(path);
		assert.deepEqual(readFileSync(path), before);
		for (const suffix of ["-wal", "-shm", "-journal"]) assert.equal(existsSync(`${path}${suffix}`), false);
		const reader = new DatabaseSync(path, { readOnly: true });
		try {
			assert.equal(reader.prepare("PRAGMA journal_mode").get()?.journal_mode, "delete");
			assert.equal(reader.prepare("SELECT count(*) AS count FROM targets").get()?.count, 0);
		} finally { reader.close(); }
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("readiness refuses substituted sidecars and missing schema without altering a sentinel", () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-ledger-probe-"));
	try {
		const path = join(root, "pluto.db");
		const database = new DatabaseSync(path); database.exec(SCHEMA_SQL); database.close();
		const sentinel = join(root, "sentinel"); writeFileSync(sentinel, "preserve fixture");
		symlinkSync(sentinel, `${path}-shm`);
		assert.throws(() => probeReadableLedger(path), /unsafe sidecar/);
		assert.equal(readFileSync(sentinel, "utf8"), "preserve fixture");
		const absent = join(root, "missing-schema.db");
		const empty = new DatabaseSync(absent); empty.close();
		assert.throws(() => probeReadableLedger(absent), /no such table/);
	} finally { rmSync(root, { recursive: true, force: true }); }
});
