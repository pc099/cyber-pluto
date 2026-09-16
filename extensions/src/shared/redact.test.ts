import assert from "node:assert/strict";
import { test } from "node:test";
import { redactSecrets } from "./redact.js";

test("redacts high-confidence secret shapes", () => {
	assert.match(redactSecrets("sshpass -p Sup3rSecret ssh nathan@10.0.0.5"), /sshpass -p \[REDACTED\]/);
	assert.match(redactSecrets('{"password":"hunter2","user":"a"}'), /"password"\s*:\s*"\[REDACTED\]/);
	assert.match(redactSecrets("Authorization: Bearer eyJhbGci.abc.def"), /Bearer \[REDACTED\]/);
	assert.match(redactSecrets("api_key=AKIAIOSFODNN7EXAMPLE"), /\[REDACTED/);
	assert.match(redactSecrets("curl -u admin:p@ssw0rd http://10.0.0.5/"), /-u admin:\[REDACTED\]/);
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nmore\n-----END OPENSSH PRIVATE KEY-----";
	assert.equal(redactSecrets(pem), "[REDACTED PRIVATE KEY]");
});

test("masks explicitly-known recovered secrets", () => {
	const out = redactSecrets("ftp login ok: nathan / Cap5t0ne_xyz", ["Cap5t0ne_xyz"]);
	assert.ok(!out.includes("Cap5t0ne_xyz"));
	assert.match(out, /\[REDACTED\]/);
});

test("does not mangle benign output and caps oversized output", () => {
	const benign = '{"rows":[{"id":1,"name":"widget"}]}';
	assert.equal(redactSecrets(benign), benign);
	const big = "A".repeat(20_000);
	const capped = redactSecrets(big);
	assert.ok(capped.length < big.length);
	assert.match(capped, /truncated/);
});
