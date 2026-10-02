import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("egress refuses foreign ownership and preserves policy on failed teardown or unknown inspection", () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-egress-fixture-"));
	const state = join(dir, "table");
	writeFileSync(join(dir, "nft"), `#!/usr/bin/env node
const fs=require('node:fs');const a=process.argv.slice(2);const p=process.env.PLUTO_QA_TABLE;
if(a.includes('list')){if(process.env.PLUTO_QA_UNKNOWN){process.stderr.write('Operation not permitted');process.exit(1)}if(!fs.existsSync(p)){process.stderr.write('No such file or directory');process.exit(1)}process.stdout.write(JSON.stringify({nftables:[{table:{family:'inet',name:'pluto_egress',comment:fs.readFileSync(p,'utf8')}}]}));}
else if(a[0]==='delete'){if(process.env.PLUTO_QA_DELETE_FAIL)process.exit(1);fs.unlinkSync(p)}
else if(a[0]==='-f'){const s=fs.readFileSync(0,'utf8');const m=s.match(/comment "([^\"]+)"/);if(!m)process.exit(1);fs.writeFileSync(p,m[1]);}
else process.exit(1);
`, { mode: 0o755 });
	const run = (verb, token, extra={}) => spawnSync(resolve("../sandbox/egress.sh"), [verb, ...(verb === "apply" ? ["127.0.0.1"] : [])], { encoding: "utf8", env: { PATH: `${dir}:${process.env.PATH}`, PLUTO_EGRESS_RUN_ID: token, PLUTO_QA_TABLE: state, ...extra } });
	try {
		writeFileSync(state, "foreign");
		assert.notEqual(run("apply", "first").status, 0);
		assert.notEqual(run("teardown", "first").status, 0);
		assert.equal(readFileSync(state,"utf8"), "foreign");
		rmSync(state);
		assert.notEqual(run("apply", "first", { PLUTO_QA_UNKNOWN: "1" }).status, 0);
		assert.equal(existsSync(state), false);
		const applied = run("apply", "first");
		assert.equal(applied.status, 0, applied.stderr);
		assert.equal(readFileSync(state,"utf8"), "pluto-run:first");
		assert.notEqual(run("teardown", "other").status, 0);
		assert.notEqual(run("teardown", "first", { PLUTO_QA_DELETE_FAIL: "1" }).status, 0);
		assert.equal(readFileSync(state,"utf8"), "pluto-run:first");
		const removed = run("teardown", "first");
		assert.equal(removed.status, 0, removed.stderr);
		assert.equal(existsSync(state), false);
		assert.equal(run("teardown", "first").status, 0);
	} finally { rmSync(dir, { recursive: true, force: true }); }
});
