#!/usr/bin/env node
/**
 * One-shot privileged promotion signer (Item 0, increment 3): reads a claim as
 * JSON on stdin, prints a base64 ed25519 signature on stdout, or exits non-zero
 * with a short stderr message. Run as ROOT.
 *
 * This is the trusted-root / testing entry point. Under the `--sandbox`
 * confinement the agent runs with `no_new_privs`, which disables setuid and so
 * disables sudo — a sudo-based helper CANNOT be reached from the sandbox. There
 * the signer is a resident root DAEMON on a unix socket (promotion-sign-daemon)
 * that the agent reaches with promotion-sign-client; both use the same signing
 * core (promotion-sign-core.ts). Connecting to a socket needs no privilege
 * escalation, so it survives `no_new_privs`.
 */
import { readFileSync } from "node:fs";
import { signClaimAsRoot } from "./promotion-sign-core.js";

try {
	const raw = readFileSync(0, "utf8");
	process.stdout.write(signClaimAsRoot(raw));
} catch (err) {
	process.stderr.write(`promotion-signer: ${err instanceof Error ? err.message : String(err)}\n`);
	process.exit(1);
}
