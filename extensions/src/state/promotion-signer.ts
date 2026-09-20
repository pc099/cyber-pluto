/**
 * Resolving the privileged Gate-1 promotion signer from the environment
 * (Item 0, increment 3). See promotion.ts for the mechanism and its honest
 * scope, and promotion-sign-cli.ts for the root helper.
 *
 * Two modes, chosen by env so the private key is only ever reachable by the
 * trust level that owns it:
 *   - PLUTO_PROMOTION_SIGNER_CMD — a command (e.g.
 *     "sudo -n /opt/pluto/bin/promotion-signer") invoked with the claim JSON on
 *     stdin, returning a base64 signature on stdout. This is the SANDBOX mode:
 *     pluto cannot read the key; only the root-owned helper behind a pinned
 *     sudoers rule can sign, and it re-verifies the claim against the state DB
 *     as root before signing.
 *   - PLUTO_PROMOTION_PRIVKEY — a path to an ed25519 private key readable by
 *     THIS process. Valid ONLY for a trusted single-operator root run (no
 *     sandbox); the key must not be pluto-readable, so this mode is never used
 *     under --sandbox.
 *   - neither — no signer. Promotions are recorded UNSIGNED and consumers treat
 *     the finding as untrusted (dev/tests, or a run predating key setup).
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import type { PromotionSigner } from "./findings-repo.js";
import { signPromotion } from "./promotion.js";

/** Shell out to the privileged signer. A non-zero exit or empty output throws,
 * which makes promote() fail loud — a promotion whose signature the privileged
 * gate refused must NOT succeed as unsigned. */
function commandSigner(cmd: string): PromotionSigner {
	const parts = cmd.trim().split(/\s+/);
	const program = parts[0];
	if (!program) throw new Error("PLUTO_PROMOTION_SIGNER_CMD is empty");
	const args = parts.slice(1);
	return (claim) => {
		const out = execFileSync(program, args, {
			input: JSON.stringify(claim),
			encoding: "utf8",
			timeout: 10_000,
			maxBuffer: 1 << 16,
		});
		const sig = out.trim();
		if (!sig) throw new Error("privileged promotion signer returned no signature");
		return sig;
	};
}

/** Sign in-process with a private key readable here (trusted root run only). The
 * key is read once at resolve time so an unreadable key fails fast and loud,
 * before any promotion is attempted. */
function privateKeySigner(keyPath: string): PromotionSigner {
	const pem = readFileSync(keyPath, "utf8");
	return (claim) => signPromotion(claim, pem);
}

export function resolveSigner(env: NodeJS.ProcessEnv = process.env): PromotionSigner | undefined {
	const cmd = env["PLUTO_PROMOTION_SIGNER_CMD"];
	if (cmd) return commandSigner(cmd);
	const keyPath = env["PLUTO_PROMOTION_PRIVKEY"];
	if (keyPath) return privateKeySigner(keyPath);
	return undefined;
}
