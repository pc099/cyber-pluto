/**
 * Evidence-integrity helpers (board fix, Jangow run). A run reported a "user
 * flag" of `d41d8cd98f00b204e9800998ecf8427e` — which is md5 of the EMPTY
 * string, and no flag file existed. The ledger stayed honest (it recorded no
 * such flag), but the narrative fabricated a capture. These helpers let the
 * harness recognize the tell: a hash of nothing / a placeholder is NOT evidence.
 *
 * This is a detector, not an interceptor — a narrative claim can't be blocked
 * mechanically, but any place that records a hash/secret as evidence can check
 * it, and the doctrine (skills) can cite the denylist so the reasoning core
 * never presents one of these as a finding.
 */

/** Hashes of the EMPTY string across common algorithms — a value derived from
 * `md5sum`/`sha*sum` of a missing or empty file. Never a real flag/secret. */
export const EMPTY_INPUT_HASHES: ReadonlySet<string> = new Set([
	"d41d8cd98f00b204e9800998ecf8427e", // md5("")
	"da39a3ee5e6b4b0d3255bfef95601890afd80709", // sha1("")
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // sha256("")
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", // sha512("")
]);

/** Obvious placeholder/sentinel evidence values — not a real capture. */
const PLACEHOLDER_VALUES: ReadonlySet<string> = new Set([
	"00000000000000000000000000000000",
	"11111111111111111111111111111111",
	"deadbeef",
	"cafebabe",
	"flag{}",
	"htb{}",
	"changeme",
	"password",
	"test",
]);

/**
 * True if `value` looks like junk evidence — the hash of nothing, an all-same-
 * digit hash, or a known placeholder. Case- and whitespace-insensitive.
 */
export function isJunkEvidence(value: string): boolean {
	const v = value.trim().toLowerCase();
	if (v.length === 0) return true;
	if (EMPTY_INPUT_HASHES.has(v)) return true;
	if (PLACEHOLDER_VALUES.has(v)) return true;
	// A hex string of a single repeated character (0000…, ffff…) is not a real hash.
	if (/^[0-9a-f]{16,}$/.test(v) && /^(.)\1+$/.test(v)) return true;
	return false;
}

/** Reason string when a value is junk, for logging/flagging. Empty if not junk. */
export function junkEvidenceReason(value: string): string {
	const v = value.trim().toLowerCase();
	if (v.length === 0) return "empty value";
	if (EMPTY_INPUT_HASHES.has(v)) return "hash of an EMPTY/missing file (not a real capture)";
	if (PLACEHOLDER_VALUES.has(v)) return "known placeholder value";
	if (isJunkEvidence(v)) return "degenerate/repeated-character hash";
	return "";
}
