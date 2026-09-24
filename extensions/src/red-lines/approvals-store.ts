/**
 * Filesystem layer for the red-line approval channel. Keeps all I/O out of
 * approvals.ts (which stays pure/testable). Two per-engagement, append-only
 * ledgers under the state dir:
 *   - red-line-blocks.jsonl     : pending blocks the gate surfaced, for `/blocks`
 *   - red-line-approvals.jsonl  : operator grants + single-use consumption marks
 */
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { stateDir } from "../state/db.js";
import { type Grant, type GrantMatchParams, type PendingBlock, grantMatches } from "./approvals.js";

const BLOCKS_FILE = "red-line-blocks.jsonl";
const APPROVALS_FILE = "red-line-approvals.jsonl";

function blocksPath(cwd: string): string {
	return join(stateDir(cwd), BLOCKS_FILE);
}
function approvalsPath(cwd: string): string {
	return join(stateDir(cwd), APPROVALS_FILE);
}

/**
 * The HMAC key for grant signatures. Resolved from OUTSIDE the pluto-writable
 * tree so that under --sandbox the confined pluto uid cannot read it (making a
 * model-forged grant line fail verification). Order: PLUTO_APPROVAL_HMAC_KEY,
 * then a root-held key file. Absent → unsigned dev mode (honest degradation; the
 * operator-only console command + the ledger-write red-line rule still stand).
 */
export function resolveApprovalKey(): string | undefined {
	const env = process.env["PLUTO_APPROVAL_HMAC_KEY"];
	if (env && env.trim().length >= 16) return env.trim();
	const path = process.env["PLUTO_APPROVAL_KEY_FILE"] ?? "/etc/cyber-pluto/approval_hmac.key";
	try {
		const k = readFileSync(path, "utf8").trim();
		return k.length >= 16 ? k : undefined;
	} catch {
		return undefined;
	}
}

function ensureDir(cwd: string): void {
	try {
		mkdirSync(stateDir(cwd), { recursive: true });
	} catch {
		/* best effort */
	}
}

/** Surface a pending block so the operator's `/blocks` can list it. Deduped by
 * blockId within the current session (the gate may re-fire the same block). */
export function recordPendingBlock(cwd: string, block: PendingBlock): void {
	ensureDir(cwd);
	try {
		const existing = readPendingBlocks(cwd);
		if (existing.some((b) => b.blockId === block.blockId)) return;
		appendFileSync(blocksPath(cwd), `${JSON.stringify(block)}\n`, "utf8");
	} catch {
		/* best effort — the block still stands regardless */
	}
}

export function readPendingBlocks(cwd: string): PendingBlock[] {
	return readJsonl<PendingBlock>(blocksPath(cwd)).filter((b) => b && typeof b.blockId === "string");
}

/** Append an operator grant (called only from the `/allow` console command). */
export function appendGrant(cwd: string, grant: Grant): void {
	ensureDir(cwd);
	appendFileSync(approvalsPath(cwd), `${JSON.stringify({ grant })}\n`, "utf8");
}

interface ConsumeMark {
	consumedId: string;
}

/**
 * Find an active grant that authorizes this exact call, and CONSUME it (single
 * use) by appending a consumption tombstone. Returns the grant, or null if none
 * matches. Called by the red-lines hook when a call would otherwise be blocked.
 */
export function consumeMatchingGrant(cwd: string, params: GrantMatchParams): Grant | null {
	const path = approvalsPath(cwd);
	if (!existsSync(path)) return null;
	const records = readJsonl<{ grant?: Grant; consumedId?: string }>(path);
	const consumed = new Set<string>();
	const grants: Grant[] = [];
	for (const r of records) {
		if (r?.consumedId) consumed.add(r.consumedId);
		else if (r?.grant) grants.push(r.grant);
	}
	for (const g of grants) {
		if (consumed.has(g.id)) continue;
		if (grantMatches(g, params)) {
			try {
				appendFileSync(path, `${JSON.stringify({ consumedId: g.id } satisfies ConsumeMark)}\n`, "utf8");
			} catch {
				// If we cannot record consumption we must NOT hand out the grant —
				// failing to a re-block is the safe direction.
				return null;
			}
			return g;
		}
	}
	return null;
}

function readJsonl<T>(path: string): T[] {
	try {
		const out: T[] = [];
		for (const line of readFileSync(path, "utf8").split("\n")) {
			const t = line.trim();
			if (!t) continue;
			try {
				out.push(JSON.parse(t) as T);
			} catch {
				/* skip malformed line */
			}
		}
		return out;
	} catch {
		return [];
	}
}
