#!/usr/bin/env node
/** Root daemon: bounded promotion/health/monotonic-stop IPC, no target I/O. */
import { execFileSync } from "node:child_process";
import { chmodSync, chownSync, lstatSync, unlinkSync } from "node:fs";
import net from "node:net";
import { assertProtectedRootParents, createPromotionAuthority } from "./promotion-sign-core.js";
import { createIsolatedPromotionAuthority, type IsolatedPromotionAuthority } from "./promotion-sign-isolated.js";
import { SIGNER_MAX_BYTES, SIGNER_TIMEOUT_MS } from "./signer-health.js";

const sockPath = process.argv[2] ?? process.env.PLUTO_PROMOTION_SIGNER_SOCK;
if (!sockPath) { process.stderr.write("promotion-sign-daemon: no socket path\n"); process.exit(1); }
const strict = process.env.PLUTO_SIGNER_STRICT === "1";
let authority: ReturnType<typeof createPromotionAuthority> | IsolatedPromotionAuthority | undefined;
let ownSocket: string | undefined;
const connections = new Set<net.Socket>();
let shuttingDown = false;
function removeOwnedSocket(): void {
	if (!ownSocket) return;
	try {
		const st = lstatSync(sockPath!);
		if (st.isSocket() && `${st.dev}:${st.ino}` === ownSocket) unlinkSync(sockPath!);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") process.stderr.write(`promotion-sign-daemon: socket cleanup: ${String(error)}\n`);
	}
}
try {
	if (strict) assertProtectedRootParents(sockPath);
	try { lstatSync(sockPath); throw new Error("existing signer endpoint; refusing replacement"); }
	catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
	// Legacy fixtures historically created their DB after daemon startup. Strict
	// launches must initialize it first; nonstrict uses the one-shot core below.
	if (strict) authority = process.env.PLUTO_SANDBOX_MODE === "requested" ? await createIsolatedPromotionAuthority() : createPromotionAuthority();
} catch (error) { process.stderr.write(`promotion-sign-daemon: ${String(error)}\n`); process.exit(1); }

const server = net.createServer({ allowHalfOpen: true }, conn => {
	if (connections.size >= 32 || shuttingDown) { conn.destroy(); return; }
	connections.add(conn);
	const chunks: Buffer[] = [];
	let length = 0;
	const timeout = setTimeout(() => conn.destroy(), SIGNER_TIMEOUT_MS);
	conn.once("close", () => { clearTimeout(timeout); connections.delete(conn); });
	conn.on("data", (data: Buffer) => {
		length += data.length;
		if (length > SIGNER_MAX_BYTES) { conn.destroy(); return; }
		chunks.push(data);
	});
	conn.on("end", async () => {
		let response: string;
		try {
			const raw = Buffer.concat(chunks).toString("utf8");
			const request: unknown = JSON.parse(raw);
			const op = request && typeof request === "object" ? (request as { op?: unknown }).op : undefined;
			if (op === "health") {
				if (!authority) throw new Error("strict health unavailable");
				const challenge = (request as { challenge?: unknown }).challenge;
				if (typeof challenge !== "string") throw new Error("missing health challenge");
				response = JSON.stringify(await authority.health(challenge));
			} else if (op === "stop") {
				if (!authority) throw new Error("strict stop unavailable");
				authority.stop(); response = "OK STOP";
			} else if (op !== undefined) { throw new Error("unknown signer operation"); }
			else if (authority) response = `OK ${await authority.sign(raw)}`;
			else {
				// Compatibility for old trusted/local fixtures, never used by sandbox launches.
				const temporary = createPromotionAuthority();
				try { response = `OK ${temporary.sign(raw)}`; } finally { temporary.close(); }
			}
		} catch (error) { response = `ERR ${error instanceof Error ? error.message.slice(0, 512) : "signer failure"}`; }
		if (Buffer.byteLength(response) > SIGNER_MAX_BYTES) response = "ERR signer response exceeds size limit";
		conn.end(response);
	});
	conn.on("error", () => conn.destroy());
});
function shutdown(code = 0): void {
	if (shuttingDown) return;
	shuttingDown = true;
	for (const conn of connections) conn.destroy();
	removeOwnedSocket();
	authority?.close();
	// Node/libuv's server.close() unlinks its original Unix pathname without
	// checking whether another inode now occupies it. This dedicated process
	// exits after our ownership-checked unlink; the OS closes its listener fd.
	process.exit(code);
}
server.on("error", error => { process.stderr.write(`promotion-sign-daemon: ${error.message}\n`); shutdown(1); });
server.listen(sockPath, () => {
	try {
		const st = lstatSync(sockPath);
		ownSocket = `${st.dev}:${st.ino}`;
		if (strict) {
			const group = Number(execFileSync("id", ["-g", process.env.PLUTO_UID ?? "pluto"], { encoding: "utf8" }).trim());
			if (!Number.isSafeInteger(group)) throw new Error("invalid signer client group");
			chownSync(sockPath, 0, group); chmodSync(sockPath, 0o660);
		} else chmodSync(sockPath, 0o666);
		process.stdout.write("listening\n");
	} catch (error) { process.stderr.write(`promotion-sign-daemon: socket setup: ${String(error)}\n`); shutdown(1); }
});
process.on("SIGINT", () => shutdown());
process.on("SIGTERM", () => shutdown());
