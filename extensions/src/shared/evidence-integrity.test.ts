/**
 * Evidence-integrity tests — the harness must recognize the empty-string-md5
 * fabrication (and kin) as NON-evidence.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { isJunkEvidence, junkEvidenceReason } from "./evidence-integrity.js";

test("the empty-string md5 (the Jangow fabrication) is junk, not a flag", () => {
	assert.ok(isJunkEvidence("d41d8cd98f00b204e9800998ecf8427e"));
	assert.match(junkEvidenceReason("d41d8cd98f00b204e9800998ecf8427e"), /empty/i);
});

test("empty-string hashes across algorithms are junk", () => {
	assert.ok(isJunkEvidence("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // sha1("")
	assert.ok(isJunkEvidence("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")); // sha256("")
	assert.ok(isJunkEvidence("  D41D8CD98F00B204E9800998ECF8427E  "), "case/space-insensitive");
});

test("placeholders and degenerate hashes are junk", () => {
	assert.ok(isJunkEvidence(""));
	assert.ok(isJunkEvidence("changeme"));
	assert.ok(isJunkEvidence("00000000000000000000000000000000"));
	assert.ok(isJunkEvidence("ffffffffffffffffffff"));
});

test("a real-looking secret/hash is NOT flagged", () => {
	assert.ok(!isJunkEvidence("abygurl69"));
	assert.ok(!isJunkEvidence("5f4dcc3b5aa765d61d8327deb882cf99")); // md5("password") — a real hash
	assert.equal(junkEvidenceReason("abygurl69"), "");
});
