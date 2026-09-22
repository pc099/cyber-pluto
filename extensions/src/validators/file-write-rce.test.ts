/**
 * Gate-1 file-write→RCE validator tests (Decision 0005). Both paths + the exact
 * conditions the board gated on: cleanup actually happened, a FAILED cleanup
 * does NOT false-negative the verdict (it flags + decouples), the lesser
 * arbitrary_file_write is preserved (not over-claimed, not dropped), and — the
 * single gating test — the baseline is captured BEFORE any write (the
 * self-poison regression from the first live run).
 *
 * Hermetic in-process server simulates a vulnerable write primitive + a minimal
 * PHP interpreter (evaluates the inert `.(7*7).` arithmetic and honors @unlink),
 * so no real target is touched.
 */
import assert from "node:assert/strict";
import { type Server, createServer } from "node:http";
import { after, test } from "node:test";
import { validateFileWriteRce } from "./file-write-rce.js";

type Mode = "rce" | "writeonly" | "readonly" | "no-cleanup";

/** A fixture server. Returns its base URL + the op-order log + the backing FS. */
async function fixture(mode: Mode): Promise<{ base: string; ops: string[]; fs: Map<string, string>; server: Server }> {
	const fs = new Map<string, string>();
	const ops: string[] = [];
	const server = createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://x");
		if (req.method === "POST" && url.pathname === "/write") {
			let body = "";
			req.on("data", (c) => {
				body += c;
			});
			req.on("end", () => {
				const p = new URLSearchParams(body);
				const name = p.get("file") ?? "";
				const content = p.get("content") ?? "";
				ops.push(`write:${name}`);
				// no-cleanup mode refuses the empty-content overwrite (and ignores unlink),
				// so the validator cannot neutralize the artifact → cleanup fails.
				if (mode === "no-cleanup" && content === "") {
					res.writeHead(200).end("ignored");
					return;
				}
				if (mode !== "readonly" && name) fs.set(name, content);
				res.writeHead(200).end("ok");
			});
			return;
		}
		// GET /files/<name>
		const m = /^\/files\/(.+)$/.exec(url.pathname);
		if (req.method === "GET" && m) {
			const name = decodeURIComponent(m[1] ?? "");
			ops.push(`get:${name}`);
			if (!fs.has(name)) return void res.writeHead(404).end("not found");
			const content = fs.get(name) ?? "";
			// Simulate PHP execution for .php in exec-capable modes.
			if (name.endsWith(".php") && (mode === "rce" || mode === "no-cleanup")) {
				const ar = /echo "([^"]*)"\.\(7\*7\)\."([^"]*)"/.exec(content);
				const out = ar ? `${ar[1]}49${ar[2]}` : "";
				if (mode === "rce") {
					// honor @unlink(__DIR__."/X") and @unlink(__FILE__)
					const um = /@unlink\(__DIR__\."\/([^"]+)"\)/.exec(content);
					if (um?.[1]) fs.delete(um[1]);
					if (/@unlink\(__FILE__\)/.test(content)) fs.delete(name);
				}
				return void res.writeHead(200).end(out);
			}
			// writeonly/readonly: serve raw (no execution).
			return void res.writeHead(200).end(content);
		}
		res.writeHead(404).end();
	});
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
	const addr = server.address();
	const port = typeof addr === "object" && addr ? addr.port : 0;
	return { base: `http://127.0.0.1:${port}`, ops, fs, server };
}

function targetFor(base: string) {
	return { writeUrl: `${base}/write`, fileField: "file", contentField: "content", fetchUrlTemplate: `${base}/files/{name}` };
}

const servers: Server[] = [];
after(() => {
	for (const s of servers) s.close();
});
async function make(mode: Mode) {
	const f = await fixture(mode);
	servers.push(f.server);
	return f;
}

test("PASS: proven file-write→RCE validates as file_write_rce with both signals", async () => {
	const f = await make("rce");
	const r = await validateFileWriteRce(targetFor(f.base));
	assert.equal(r.validator, "file_write_rce");
	assert.equal(r.passed, true);
	assert.equal(r.technicalSignal, true);
	assert.equal(r.impactArtifact, true);
});

test("CLEANUP happened: planted artifacts are gone afterward, no alert", async () => {
	const f = await make("rce");
	const r = await validateFileWriteRce(targetFor(f.base));
	assert.ok(!r.cleanupFailed, "cleanup should have succeeded");
	// The backing FS holds no pluto artifact.
	const leftover = [...f.fs.keys()].filter((k) => k.startsWith("pluto_"));
	assert.deepEqual(leftover, [], `no artifact should remain, found: ${leftover}`);
});

test("CLEANUP FAILED does NOT flip the verdict (decoupled) — it flags + alerts", async () => {
	const f = await make("no-cleanup");
	const r = await validateFileWriteRce(targetFor(f.base));
	assert.equal(r.passed, true, "a proven compromise must stay passed even if cleanup fails");
	assert.equal(r.impactArtifact, true);
	assert.equal(r.cleanupFailed, true);
	assert.ok((r.artifactRefs ?? []).length > 0, "must record where the artifact remains");
	assert.match(r.diffSummary, /ARTIFACT MAY REMAIN/);
});

test("write-only (no execution) is the lesser arbitrary_file_write, not over-claimed as RCE, not dropped", async () => {
	const f = await make("writeonly");
	const r = await validateFileWriteRce(targetFor(f.base));
	assert.equal(r.validator, "arbitrary_file_write");
	assert.equal(r.passed, true);
	assert.equal(r.technicalSignal, true);
	assert.equal(r.impactArtifact, false);
});

test("no write at all → not passed (reject path)", async () => {
	const f = await make("readonly");
	const r = await validateFileWriteRce(targetFor(f.base));
	assert.equal(r.passed, false);
	assert.equal(r.technicalSignal, false);
});

test("GATING: the baseline GET happens BEFORE the first write (kills the self-poison bug)", async () => {
	const f = await make("rce");
	const r = await validateFileWriteRce(targetFor(f.base));
	const firstWrite = f.ops.findIndex((o) => o.startsWith("write:"));
	const firstGet = f.ops.findIndex((o) => o.startsWith("get:"));
	assert.ok(firstGet >= 0 && firstGet < firstWrite, `baseline GET (op ${firstGet}) must precede the first write (op ${firstWrite}); ops=${f.ops.slice(0, 4)}`);
	// And the baseline evidence did not already contain the content-nonce.
	assert.ok(r.baseline && (r.baseline.status === 404 || r.baseline.body === ""), "baseline must be an absent/empty path, never a self-poisoned one");
});
