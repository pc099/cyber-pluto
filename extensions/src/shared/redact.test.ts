import assert from "node:assert/strict";
import { test } from "node:test";
import { capField, redactSecrets } from "./redact.js";

test("redacts high-confidence secret shapes", () => {
	assert.match(redactSecrets("sshpass -p Sup3rSecret ssh nathan@10.0.0.5"), /sshpass -p \[REDACTED\]/);
	assert.match(redactSecrets('{"password":"hunter2","user":"a"}'), /"password"\s*:\s*"\[REDACTED\]/);
	assert.match(redactSecrets("Authorization: Bearer eyJhbGci.abc.def"), /Bearer \[REDACTED\]/);
	assert.match(redactSecrets("api_key=AKIAIOSFODNN7EXAMPLE"), /\[REDACTED/);
	assert.match(redactSecrets("curl -u admin:p@ssw0rd http://10.0.0.5/"), /-u admin:\[REDACTED\]/);
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nmore\n-----END OPENSSH PRIVATE KEY-----";
	assert.equal(redactSecrets(pem), "[REDACTED PRIVATE KEY]");
});

test("redacts provider keys/tokens by prefix shape (the class of the ANTHROPIC key leak)", () => {
	assert.match(redactSecrets("key is sk-ant-api03-pAoBI0a3vzIFlpS8BlSnj9vq0n-3QWhPVG9iV5vi and done"), /\[REDACTED KEY\]/);
	assert.ok(!redactSecrets("sk-ant-api03-pAoBI0a3vzIFlpS8BlSnj9vq0n-3QWhPVG9iV5vi").includes("pAoBI0"));
	for (const k of ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "gsk_ABCDEFGHIJKLMNOPqrstuvwx", "xai-ABCDEFGHIJKLMNOPqrstuvwx"]) {
		assert.match(redactSecrets(`tok=${k}`), /\[REDACTED KEY\]/);
	}
});

test("masks explicitly-known recovered secrets", () => {
	const out = redactSecrets("ftp login ok: nathan / Cap5t0ne_xyz", ["Cap5t0ne_xyz"]);
	assert.ok(!out.includes("Cap5t0ne_xyz"));
	assert.match(out, /\[REDACTED\]/);
});

test("redactSecrets does not mangle benign output and does NOT truncate", () => {
	const benign = '{"rows":[{"id":1,"name":"widget"}]}';
	assert.equal(redactSecrets(benign), benign);
	const big = "A".repeat(20_000);
	assert.equal(redactSecrets(big).length, big.length, "redactSecrets must not truncate (would corrupt JSONL)");
});

test("capField truncates an oversized field but leaves small values as-is", () => {
	const small = { id: 1, name: "widget" };
	assert.deepEqual(capField(small), small);
	const capped = capField("A".repeat(20_000));
	assert.ok(typeof capped === "string" && capped.length < 20_000);
	assert.match(capped as string, /truncated/);
	// A JSONL line built from a capped field must still be valid JSON.
	assert.doesNotThrow(() => JSON.parse(JSON.stringify({ result: capField("B".repeat(50_000)) })));
});
