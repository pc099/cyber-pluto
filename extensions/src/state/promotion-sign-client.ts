#!/usr/bin/env node
/** Unprivileged bounded client; it holds no key or validation authority. */
import { readSync } from "node:fs";
import { requestOperatorStop, signerRequest, SIGNER_MAX_BYTES } from "./signer-health.js";

const sockPath = process.argv[2] ?? process.env.PLUTO_PROMOTION_SIGNER_SOCK;
if (!sockPath) { process.stderr.write("promotion-sign-client: no socket path\n"); process.exit(1); }
try {
	if (process.argv[3] === "--stop") { await requestOperatorStop(sockPath); process.exit(0); }
	const buffer = Buffer.alloc(SIGNER_MAX_BYTES + 1);
	let size = 0;
	while (size < buffer.length) { const count = readSync(0, buffer, size, buffer.length - size, null); if (!count) break; size += count; }
	if (size > SIGNER_MAX_BYTES) throw new Error("signer request exceeds size limit");
	const response = await signerRequest(sockPath, buffer.subarray(0, size).toString("utf8"));
	if (!response.startsWith("OK ")) throw new Error(response.replace(/^ERR /, "").slice(0, 512));
	process.stdout.write(response.slice(3));
} catch (error) { process.stderr.write(`promotion-signer: ${error instanceof Error ? error.message : "request failed"}\n`); process.exit(1); }
