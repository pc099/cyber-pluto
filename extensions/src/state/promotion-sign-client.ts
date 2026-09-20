#!/usr/bin/env node
/**
 * The promotion-signing client (Item 0, increment 3): the thin, UNPRIVILEGED
 * side the confined agent runs. It reads a claim JSON on stdin, sends it to the
 * root daemon over the unix socket, and prints the returned base64 signature on
 * stdout (or exits non-zero on an "ERR" reply). It holds no key and makes no
 * trust decision — the daemon's root core does all of that.
 *
 * resolveSigner() reaches this via PLUTO_PROMOTION_SIGNER_CMD, e.g.
 *   PLUTO_PROMOTION_SIGNER_CMD="node .../promotion-sign-client.js <socket>"
 * so the existing synchronous execFileSync signer path is reused unchanged.
 *
 * Usage: promotion-sign-client <socket-path>   (claim JSON on stdin)
 */
import { readFileSync } from "node:fs";
import net from "node:net";

const sockPath = process.argv[2] ?? process.env["PLUTO_PROMOTION_SIGNER_SOCK"];
if (!sockPath) {
	process.stderr.write("promotion-sign-client: no socket path (argv[2] or PLUTO_PROMOTION_SIGNER_SOCK)\n");
	process.exit(1);
}

let input: Buffer;
try {
	input = readFileSync(0);
} catch (err) {
	process.stderr.write(`promotion-sign-client: cannot read stdin: ${err instanceof Error ? err.message : String(err)}\n`);
	process.exit(1);
}

const conn = net.connect(sockPath);
const chunks: Buffer[] = [];
conn.on("connect", () => conn.end(input));
conn.on("data", (d) => chunks.push(d));
conn.on("error", (err) => {
	process.stderr.write(`promotion-sign-client: ${err.message}\n`);
	process.exit(1);
});
conn.on("close", () => {
	const resp = Buffer.concat(chunks).toString("utf8");
	if (resp.startsWith("OK ")) {
		process.stdout.write(resp.slice(3));
		process.exit(0);
	}
	process.stderr.write(`promotion-signer: ${resp.replace(/^ERR /, "")}\n`);
	process.exit(1);
});
