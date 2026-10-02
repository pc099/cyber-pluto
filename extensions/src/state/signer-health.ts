/** Bounded signer IPC. Health signatures use a different domain from promotions. */
import { createHash, createPublicKey, randomBytes, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import net from "node:net";

export const SIGNER_MAX_BYTES = 16 * 1024;
export const SIGNER_TIMEOUT_MS = 2000;
export interface SignerHealthClaim {
	schema: 1;
	ledgerPath: string;
	runId: string;
	challenge: string;
	keyFingerprint: string;
	databaseIdentity: string;
}
export function publicKeyFingerprint(key: KeyObject): string {
	return createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}
export function canonicalHealth(claim: SignerHealthClaim): string {
	return "PLUTO_SIGNER_HEALTH_V1\0" + JSON.stringify([claim.schema, claim.ledgerPath, claim.runId, claim.challenge, claim.keyFingerprint, claim.databaseIdentity]);
}
export function signerRequest(socketPath: string, request: string, timeoutMs = SIGNER_TIMEOUT_MS): Promise<string> {
	if (Buffer.byteLength(request) > SIGNER_MAX_BYTES) return Promise.reject(new Error("signer request exceeds size limit"));
	return new Promise((resolve, reject) => {
		const conn = net.connect(socketPath);
		const chunks: Buffer[] = [];
		let length = 0;
		let settled = false;
		const finish = (error?: Error, result?: string): void => {
			if (settled) return;
			settled = true; clearTimeout(timer); conn.destroy();
			if (error) reject(error); else resolve(result ?? "");
		};
		const timer = setTimeout(() => finish(new Error("signer request timed out")), timeoutMs);
		conn.on("connect", () => conn.end(request));
		conn.on("data", (data: Buffer) => {
			length += data.length;
			if (length > SIGNER_MAX_BYTES) { finish(new Error("signer response exceeds size limit")); return; }
			chunks.push(data);
		});
		conn.on("error", error => finish(error));
		conn.on("end", () => finish(undefined, Buffer.concat(chunks).toString("utf8")));
		conn.on("close", () => { if (!settled) finish(new Error("signer closed without a complete response")); });
	});
}
export async function checkSignerHealth(options: {
	socketPath: string; ledgerPath: string; runId: string; publicKeyPath: string; timeoutMs?: number;
}): Promise<SignerHealthClaim> {
	const key = createPublicKey(readFileSync(options.publicKeyPath));
	if (key.asymmetricKeyType !== "ed25519") throw new Error("signer public key must be ed25519");
	const challenge = randomBytes(32).toString("hex");
	const raw = await signerRequest(options.socketPath, JSON.stringify({ op: "health", challenge }), options.timeoutMs);
	let reply: { claim?: SignerHealthClaim; signature?: string };
	try { reply = JSON.parse(raw) as typeof reply; } catch { throw new Error("signer health response is invalid"); }
	const c = reply.claim;
	if (!c || c.schema !== 1 || c.ledgerPath !== options.ledgerPath || c.runId !== options.runId || c.challenge !== challenge ||
		c.keyFingerprint !== publicKeyFingerprint(key) || typeof c.databaseIdentity !== "string" || !/^\d+:\d+$/.test(c.databaseIdentity) ||
		typeof reply.signature !== "string" || !verify(null, Buffer.from(canonicalHealth(c)), key, Buffer.from(reply.signature, "base64"))) {
		throw new Error("signer health authentication or ledger/run binding failed");
	}
	return c;
}
/** Monotonic stop only: the root daemon selects the protected path, never the caller. */
export async function requestOperatorStop(socketPath: string): Promise<void> {
	const response = await signerRequest(socketPath, JSON.stringify({ op: "stop" }));
	if (response !== "OK STOP") throw new Error(`signer stop refused: ${response.slice(0, 512)}`);
}
