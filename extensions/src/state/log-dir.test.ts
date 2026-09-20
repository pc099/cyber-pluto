/**
 * logDir redirect (QA condition C2 on the Shodan gate, and the broader audit
 * trail). Under --sandbox the repo root is read-only, so logs must be
 * redirectable to a pluto-writable per-engagement dir or "everything is logged"
 * breaks silently. This proves the redirect the launcher relies on.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { logDir } from "./db.js";

test("logDir defaults to repo-root logs/ when PLUTO_LOG_DIR is unset (non-sandbox, unchanged)", () => {
	const saved = process.env["PLUTO_LOG_DIR"];
	delete process.env["PLUTO_LOG_DIR"];
	try {
		assert.equal(logDir("/repo"), "/repo/logs");
	} finally {
		if (saved !== undefined) process.env["PLUTO_LOG_DIR"] = saved;
	}
});

test("logDir honors PLUTO_LOG_DIR (the sandbox-writable redirect)", () => {
	const saved = process.env["PLUTO_LOG_DIR"];
	process.env["PLUTO_LOG_DIR"] = "engagements/box1/logs";
	try {
		assert.equal(logDir("/repo"), "engagements/box1/logs");
	} finally {
		if (saved === undefined) delete process.env["PLUTO_LOG_DIR"];
		else process.env["PLUTO_LOG_DIR"] = saved;
	}
});
