/**
 * Evidence hashing for Gate-1 promotion binding (Decision 0002, increment 2).
 *
 * The signed promotion claim binds a hash of the evidence bytes so a consumer
 * (and the Gate-2 human) can detect evidence that was ALTERED AFTER signing: the
 * signature covers this hash, and a verifier re-hashes the current file and
 * compares. SCOPE (honest, per QA): this catches POST-sign tampering only — a
 * PRE-sign forge that writes self-consistent fake evidence hashes fine and still
 * passes (the forge sentinel stays green). It is NOT a forge closure.
 *
 * Used by BOTH the in-realm promote() (to compute the hash it stores) and the
 * privileged signer core (to compute the hash it signs) via this one function,
 * so the two never drift. Deterministic; a missing file contributes nothing (a
 * promotion with no readable evidence hashes to "" — no binding, unchanged
 * behavior).
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** SHA-256 (hex) over the named evidence files' contents, each domain-separated
 * by its ref. Returns "" when no ref is readable. `cwd`-relative refs. */
export function hashEvidence(cwd: string, refs: Array<string | null | undefined>): string {
	const h = createHash("sha256");
	let any = false;
	for (const ref of refs) {
		if (!ref) continue;
		let buf: Buffer;
		try {
			buf = readFileSync(join(cwd, ref));
		} catch {
			continue; // missing/unreadable → contributes nothing
		}
		h.update(ref);
		h.update("\0");
		h.update(buf);
		h.update("\0");
		any = true;
	}
	return any ? h.digest("hex") : "";
}
