/**
 * Both-paths test for the IDOR validator: it must confirm cross-owner access
 * to a protected object and REJECT when the resource is public or non-
 * differential. Uses an inline Cap-shaped fixture (session required; /data/0 =
 * another owner's data; /data/<you> = your own; /pub/0 = public control).
 */
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { test } from "node:test";
import { validateIdor } from "./idor.js";

function fixture(): Server {
	return createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		const hasSession = /session=ok/.test(req.headers.cookie ?? "");
		const m = /^\/data\/(\d+)$/.exec(url.pathname);
		const pub = /^\/pub\/(\d+)$/.exec(url.pathname);
		if (m) {
			if (!hasSession) {
				res.writeHead(401);
				res.end("no session");
				return;
			}
			const id = Number(m[1]);
			res.writeHead(200, { "content-type": "application/octet-stream" });
			res.end(id === 0 ? "ADMIN SECRET CAPTURE DATA nathan:pw" : `your own empty snapshot ${id}`);
			return;
		}
		if (pub) {
			// public: returns data regardless of session — NOT an IDOR.
			res.writeHead(200);
			res.end(`public record ${pub[1]} with distinct content here`);
			return;
		}
		res.writeHead(404);
		res.end("nf");
	});
}

function listen(s: Server): Promise<number> {
	return new Promise((r) => s.listen(0, "127.0.0.1", () => {
		const a = s.address();
		r(typeof a === "object" && a ? a.port : 0);
	}));
}

test("IDOR confirmed: cross-owner access to a protected object", async () => {
	const s = fixture();
	const port = await listen(s);
	try {
		const report = await validateIdor({
			ownUrl: `http://127.0.0.1:${port}/data/3`,
			otherUrl: `http://127.0.0.1:${port}/data/0`,
			headers: { Cookie: "session=ok" },
		});
		assert.equal(report.passed, true);
		assert.ok(report.steps.find((s) => s.name === "differential-access")?.passed);
		assert.ok(report.steps.find((s) => s.name === "access-controlled")?.passed);
	} finally {
		s.close();
	}
});

test("IDOR rejected: a public resource is not broken access control", async () => {
	const s = fixture();
	const port = await listen(s);
	try {
		const report = await validateIdor({
			ownUrl: `http://127.0.0.1:${port}/pub/3`,
			otherUrl: `http://127.0.0.1:${port}/pub/0`,
			headers: { Cookie: "session=ok" },
		});
		assert.equal(report.passed, false, "public resource must not be flagged as IDOR");
	} finally {
		s.close();
	}
});
