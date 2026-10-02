/** Root key holder with private bounded IPC to a persistent confined reader.
 * No SQLite connection or query occurs in this production authority. */
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstatSync } from "node:fs";
import { dirname, join } from "node:path";
import { createSigningContext } from "./promotion-sign-core.js";
import type { PromotionClaim } from "./promotion.js";
import { SIGNER_MAX_BYTES, SIGNER_TIMEOUT_MS, type SignerHealthClaim } from "./signer-health.js";

export function checkedReaderClaim(value: unknown, findingId: number, validationId: number): PromotionClaim {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid reader claim");
	const row = value as Partial<PromotionClaim>;
	if (Object.keys(row).sort().join(",") !== "evidenceRef,findingId,targetId,validationId,validator" || row.findingId !== findingId || row.validationId !== validationId ||
		!Number.isSafeInteger(row.targetId) || Number(row.targetId) <= 0 || typeof row.validator !== "string" || row.validator.length > 128 ||
		typeof row.evidenceRef !== "string" || row.evidenceRef.length > 4096) throw new Error("Reader claim fields or correlation invalid");
	return row as PromotionClaim;
}

interface Pending { resolve(value: unknown): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }
/** Fixed private pipe, bounded frames and outstanding operations. Any transport
 * error invalidates the reader permanently; timeout never falls back to root. */
export class PromotionReaderChannel {
	private sequence = 0;
	private readonly pending = new Map<number, Pending>();
	private buffered = Buffer.alloc(0);
	private fault: Error | undefined;
	constructor(private readonly child: ChildProcessWithoutNullStreams, private readonly timeoutMs = SIGNER_TIMEOUT_MS) {
		child.on("error", error => this.fail(error));
		child.on("exit", () => this.fail(new Error("Confined signing reader exited")));
		child.stdin.on("error", error => this.fail(error));
		child.stdout.on("error", error => this.fail(error));
		child.stdout.on("data", (chunk: Buffer) => {
			this.buffered = Buffer.concat([this.buffered, chunk]);
			if (this.buffered.length > SIGNER_MAX_BYTES) { this.fail(new Error("Reader reply exceeds size limit")); return; }
			let boundary: number;
			while (!this.fault && (boundary = this.buffered.indexOf(10)) >= 0) {
				const frame = this.buffered.subarray(0, boundary).toString("utf8"); this.buffered = this.buffered.subarray(boundary + 1);
				try {
					const reply = JSON.parse(frame) as { seq?: unknown; ok?: unknown; error?: unknown };
					if (!reply || Array.isArray(reply) || !Number.isSafeInteger(reply.seq) || typeof reply.ok !== "boolean") throw new Error("Malformed reader reply");
					const waiting = this.pending.get(Number(reply.seq));
					if (!waiting) throw new Error("Reader reply correlation invalid");
					if (!reply.ok && (typeof reply.error !== "string" || reply.error.length > 512)) throw new Error("Malformed reader refusal");
					this.pending.delete(Number(reply.seq)); clearTimeout(waiting.timer);
					if (reply.ok) waiting.resolve(reply); else waiting.reject(new Error(String(reply.error)));
				} catch (error) { this.fail(error instanceof Error ? error : new Error("Invalid reader response")); }
			}
		});
		// Diagnostics are bounded by the worker; never inherit a provider/key env.
		child.stderr.on("data", (chunk: Buffer) => process.stderr.write(chunk.subarray(0, 512)));
	}
	private fail(error: Error): void {
		if (this.fault) return;
		this.fault = error;
		for (const waiting of this.pending.values()) { clearTimeout(waiting.timer); waiting.reject(error); }
		this.pending.clear(); this.child.stdin.destroy(); this.child.kill("SIGKILL");
	}
	request(operation: Record<string, unknown>): Promise<unknown> {
		if (this.fault) return Promise.reject(this.fault);
		if (this.pending.size >= 32) return Promise.reject(new Error("Reader operation limit reached"));
		const seq = ++this.sequence;
		const frame = `${JSON.stringify({ seq, ...operation })}\n`;
		if (Buffer.byteLength(frame) > SIGNER_MAX_BYTES) return Promise.reject(new Error("Reader request exceeds size limit"));
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => this.fail(new Error("Confined signing reader timed out")), this.timeoutMs);
			this.pending.set(seq, { resolve, reject, timer });
			this.child.stdin.write(frame, error => { if (error) this.fail(error); });
		});
	}
	close(): void { this.fail(new Error("Confined signing reader closed")); }
}

export interface IsolatedPromotionAuthority {
	ledgerPath: string;
	assertLedger(): void;
	sign(rawJson: string): Promise<string>;
	health(challenge: string): Promise<{ claim: SignerHealthClaim; signature: string }>;
	stop(): void;
	close(): void;
}

export function signingReaderEnvironment(env: NodeJS.ProcessEnv, uid: number): NodeJS.ProcessEnv {
	const safe: NodeJS.ProcessEnv = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/nonexistent", PLUTO_UID: "pluto", PLUTO_SANDBOX_MODE: "requested", PLUTO_READINESS_UID: String(uid) };
	for (const name of ["PLUTO_CWD", "PLUTO_STATE_DIR", "PLUTO_RUN_DIR", "PLUTO_CONTROL_DIR", "PLUTO_SIGNER_DIR", "PLUTO_PROMOTION_SIGNER_CMD", "PLUTO_PROMOTION_PUBKEY", "PI_CODING_AGENT_DIR"]) {
		if (!env[name]) throw new Error(`Confined signing reader missing ${name}`);
		safe[name] = env[name];
	}
	return safe;
}

export async function createIsolatedPromotionAuthority(env: NodeJS.ProcessEnv = process.env): Promise<IsolatedPromotionAuthority> {
	if (process.getuid?.() !== 0 || env.PLUTO_SIGNER_STRICT !== "1" || env.PLUTO_SANDBOX_MODE !== "requested") throw new Error("Isolated signing requires strict root sandbox mode");
	const context = createSigningContext(env);
	const uid = Number(execFileSync("id", ["-u", "pluto"], { encoding: "utf8" }).trim());
	if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error("Confined signing reader identity unavailable");
	const runtime = env.PLUTO_CWD!;
	const child = spawn(join(runtime, "sandbox/run-sandboxed.sh"), [dirname(env.PLUTO_STATE_DIR!), "--", process.execPath, join(runtime, "extensions/dist/state/promotion-reader.js")], {
		cwd: runtime, env: signingReaderEnvironment(env, uid), stdio: ["pipe", "pipe", "pipe"], detached: false,
	});
	const channel = new PromotionReaderChannel(child);
	const readiness = async (): Promise<void> => {
		context.assertLedger();
		const reply = await channel.request({ op: "ready" }) as { ready?: { ledgerIdentity?: unknown; uid?: unknown; noNewPrivileges?: unknown } };
		context.assertLedger();
		const ledger = lstatSync(context.ledgerPath);
		if (reply.ready?.ledgerIdentity !== `${ledger.dev}:${ledger.ino}` || reply.ready.uid !== uid || reply.ready.noNewPrivileges !== true) {
			channel.close(); throw new Error("Reader readiness identity mismatch");
		}
	};
	try { await readiness(); } catch (error) { channel.close(); throw error; }
	return {
		ledgerPath: context.ledgerPath, assertLedger: context.assertLedger, stop: context.stop, close: () => channel.close(),
		async sign(rawJson) {
			context.assertLedger();
			const request = JSON.parse(rawJson) as { findingId?: unknown; validationId?: unknown };
			if (!request || !Number.isSafeInteger(request.findingId) || Number(request.findingId) <= 0 || !Number.isSafeInteger(request.validationId) || Number(request.validationId) <= 0) throw new Error("Signing requires positive integer findingId and validationId");
			const findingId = Number(request.findingId), validationId = Number(request.validationId);
			const reply = await channel.request({ op: "claim", findingId, validationId }) as { claim?: unknown };
			const claim = checkedReaderClaim(reply.claim, findingId, validationId);
			context.assertLedger(); return context.signClaim(claim);
		},
		async health(challenge) { await readiness(); return context.health(challenge); },
	};
}
