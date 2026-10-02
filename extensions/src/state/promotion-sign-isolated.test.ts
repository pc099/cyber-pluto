import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { checkedReaderClaim, PromotionReaderChannel, signingReaderEnvironment } from "./promotion-sign-isolated.js";
import { createPromotionAuthority } from "./promotion-sign-core.js";
import { SIGNER_MAX_BYTES } from "./signer-health.js";
import { DatabaseSync } from "node:sqlite";
import { assertPromotionReaderSchema } from "./promotion-reader.js";

test("reader fixed-query schema refuses views, virtual tables and missing tables", () => {
	for (const replacement of ["CREATE VIEW findings AS SELECT 1 AS id", "CREATE VIRTUAL TABLE findings USING fts5(id)", ""]) {
		const db = new DatabaseSync(":memory:");
		try {
			db.exec("CREATE TABLE findings(id INTEGER); CREATE TABLE validations(id INTEGER)");
			assert.doesNotThrow(() => assertPromotionReaderSchema(db));
			db.exec("DROP TABLE findings");
			if (replacement) db.exec(replacement);
			assert.throws(() => assertPromotionReaderSchema(db), /ordinary/);
		} finally { db.close(); }
	}
});

test("root refuses the legacy SQLite path in requested sandbox before looking up keys or files", () => {
	assert.throws(() => createPromotionAuthority({ PLUTO_SANDBOX_MODE: "requested" }), /confined signing reader/);
});

test("reader environment excludes provider/key/host initialization settings", () => {
	const source: NodeJS.ProcessEnv = {
		PLUTO_CWD: "/opt/cyber-pluto", PLUTO_STATE_DIR: "/var/lib/cyber-pluto/engagements/fixture/state",
		PLUTO_RUN_DIR: "/run/cyber-pluto", PLUTO_CONTROL_DIR: "/var/lib/cyber-pluto/control", PLUTO_SIGNER_DIR: "/run/cyber-pluto/signers/fixture",
		PLUTO_PROMOTION_SIGNER_CMD: "fixed client", PLUTO_PROMOTION_PUBKEY: "/etc/cyber-pluto/public.pub", PI_CODING_AGENT_DIR: "/var/lib/cyber-pluto/engagements/fixture/pi-agent",
		PLUTO_PROMOTION_PRIVKEY: "/etc/cyber-pluto/private.key", PLUTO_CODEX_ACCESS_TOKEN: "synthetic-token", OPENAI_API_KEY: "synthetic-key", NODE_OPTIONS: "untrusted", BASH_ENV: "/tmp/untrusted", PLUTO_UID: "root",
	};
	const safe = signingReaderEnvironment(source, 994);
	for (const name of ["PLUTO_PROMOTION_PRIVKEY", "PLUTO_CODEX_ACCESS_TOKEN", "OPENAI_API_KEY", "NODE_OPTIONS", "BASH_ENV"]) assert.equal(safe[name], undefined);
	assert.equal(safe.PLUTO_UID, "pluto"); assert.equal(safe.PLUTO_READINESS_UID, "994");
	assert.throws(() => signingReaderEnvironment({}, 994), /missing/);
});

test("root accepts only bounded correlated typed claims from its reader", () => {
	const claim = { findingId: 1, validationId: 2, validator: "fixture", targetId: 3, evidenceRef: "fixture-only" };
	assert.deepEqual(checkedReaderClaim(claim, 1, 2), claim);
	for (const invalid of [null, [], { ...claim, findingId: 8 }, { ...claim, validationId: 9 }, { ...claim, targetId: "3" }, { ...claim, targetId: 0 }, { ...claim, validator: "x".repeat(129) }, { ...claim, evidenceRef: "x".repeat(4097) }, { ...claim, arbitraryBytes: "do not sign" }]) {
		assert.throws(() => checkedReaderClaim(invalid, 1, 2), /reader claim/i);
	}
});

test("private reader IPC correlates replies and fails permanently on bad frames, timeout or exit", async () => {
	for (const mode of ["ok", "refuse", "malformed", "wrong-sequence", "oversize", "stall", "exit"]) {
		const code = `process.stdin.once('data', chunk => {
 const input = JSON.parse(chunk.toString()); const mode = process.argv[1];
 if(mode==='exit')process.exit(1);
 if(mode==='stall')return;
 if(mode==='oversize')process.stdout.write('x'.repeat(${SIGNER_MAX_BYTES + 1}));
 else if(mode==='malformed')process.stdout.write('not-json\\n');
 else process.stdout.write(JSON.stringify({seq:mode==='wrong-sequence'?input.seq+1:input.seq,ok:mode!=='refuse',error:mode==='refuse'?'validation did not pass':undefined,ready:{fixture:true}})+'\\n');
});`;
		const child = spawn(process.execPath, ["-e", code, mode], { stdio: ["pipe", "pipe", "pipe"], env: { PATH: process.env.PATH } });
		const exited = new Promise<void>(resolve => child.once("exit", () => resolve()));
		const channel = new PromotionReaderChannel(child, 500);
		try {
			if (mode === "ok") assert.deepEqual(await channel.request({ op: "ready" }), { seq: 1, ok: true, ready: { fixture: true } });
			else {
				await assert.rejects(channel.request({ op: "ready" }), /did not pass|Unexpected|JSON|correlation|size limit|timed out|exited/);
				if (mode !== "refuse") await assert.rejects(channel.request({ op: "ready" }));
			}
		} finally { channel.close(); await exited; }
	}
});
