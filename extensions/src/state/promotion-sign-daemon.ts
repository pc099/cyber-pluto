#!/usr/bin/env node
/**
 * The resident PRIVILEGED promotion-signing daemon (Item 0, increment 3), run as
 * ROOT by the launcher before it drops to the confined `pluto` uid.
 *
 * Why a daemon and not sudo: the sandbox runs the agent under
 * `setpriv --no-new-privs`, which disables setuid and therefore sudo — a
 * sudo-based helper is unreachable from the sandbox. A unix-socket daemon needs
 * no privilege escalation to reach (connecting to a socket is not setuid), so it
 * works under `no_new_privs`. The daemon holds the private key (root-only) and
 * listens on a socket placed in the pluto-writable engagement dir, which bwrap
 * binds into the sandbox.
 *
 * Protocol (one request per connection): the client writes the claim JSON and
 * half-closes; the daemon replies "OK <base64sig>" or "ERR <message>" and
 * closes. All signing decisions are made by the shared root core
 * (promotion-sign-core.ts), which re-derives and re-verifies the claim against
 * the DB as root.
 *
 * Usage (root): promotion-sign-daemon <socket-path>
 * It prints "listening" on stdout once the socket is ready (the launcher waits
 * for the socket to appear before starting the agent).
 */
import { existsSync, unlinkSync } from "node:fs";
import { chmod } from "node:fs/promises";
import net from "node:net";
import { signClaimAsRoot } from "./promotion-sign-core.js";

const sockPath = process.argv[2] ?? process.env["PLUTO_PROMOTION_SIGNER_SOCK"];
if (!sockPath) {
	process.stderr.write("promotion-sign-daemon: no socket path (argv[2] or PLUTO_PROMOTION_SIGNER_SOCK)\n");
	process.exit(1);
}
// Remove a stale socket from a previous run so bind succeeds.
if (existsSync(sockPath)) {
	try {
		unlinkSync(sockPath);
	} catch {
		/* fall through; listen() will surface a real problem */
	}
}

const server = net.createServer((conn) => {
	const chunks: Buffer[] = [];
	conn.on("data", (d) => chunks.push(d));
	conn.on("end", () => {
		let resp: string;
		try {
			resp = `OK ${signClaimAsRoot(Buffer.concat(chunks).toString("utf8"))}`;
		} catch (err) {
			resp = `ERR ${err instanceof Error ? err.message : String(err)}`;
		}
		conn.end(resp);
	});
	conn.on("error", () => {
		/* a client hangup is not the daemon's problem */
	});
});

server.on("error", (err) => {
	process.stderr.write(`promotion-sign-daemon: ${err.message}\n`);
	process.exit(1);
});

server.listen(sockPath, () => {
	// pluto runs under a different uid, so it needs connect (write) permission on
	// the socket. The engagement dir is 0770 pluto:pluto (no other users), so a
	// world-connectable socket inside it is not a broader exposure.
	chmod(sockPath, 0o666)
		.then(() => process.stdout.write("listening\n"))
		.catch((err) => {
			process.stderr.write(`promotion-sign-daemon: chmod socket: ${err.message}\n`);
			process.exit(1);
		});
});

function shutdown(): void {
	try {
		server.close();
		if (sockPath && existsSync(sockPath)) unlinkSync(sockPath);
	} catch {
		/* best effort */
	}
	process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
