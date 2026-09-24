/**
 * Run-summary telemetry (Decision 0006 owed item). A persisted, machine-
 * comparable record of how a run went, so the board can review and compare runs
 * as LEDGER FACTS instead of re-reading transcripts. Written to the engagement
 * state dir at every deterministic stop point.
 *
 * The "how far did it get" field is DERIVED from ledger facts, not a mutable
 * phase column: the schema has a `phase` field but nothing advances it, so
 * trusting it would be dishonest. Instead the milestone is computed from what
 * was actually proven — attempts < candidates < foothold < root — the same
 * status-is-the-fact-ledger principle as the two gates.
 */

/** Ordered milestones; `reached` is the highest one whose evidence exists. */
export type Milestone = "started" | "recon" | "surface_mapped" | "candidate_found" | "foothold" | "root";

const MILESTONE_ORDER: Milestone[] = ["started", "recon", "surface_mapped", "candidate_found", "foothold", "root"];

export interface RunSummaryInput {
	targetLabel: string;
	host: string | null;
	/** Why the run stopped (hard cap, headless pause, operator, or "in_progress"). */
	stopReason: string;
	counts: { candidate: number; validated: number; submitted: number; rejected: number };
	/** validated findings that FAIL Gate-1 signature (possible tampering). */
	untrustedValidated: number;
	credsRecovered: number;
	nodeCount: number;
	attemptCount: number;
	/** Attempts bucketed by attack class (from the try-budget classifier). */
	attemptsByClass: Record<string, number>;
	/** A validated code-execution foothold exists (promotion-backed). */
	hasFoothold: boolean;
	/** A validated privilege_escalation (root) exists (promotion-backed). */
	hasRoot: boolean;
	elapsedSeconds: number;
	contextTokensSeen: number;
}

export interface RunSummary extends RunSummaryInput {
	schema: 1;
	ts: string;
	reached: Milestone;
	/** Trustworthy validated = validated minus signature-failing ones. */
	trustworthyValidated: number;
}

function deriveMilestone(i: RunSummaryInput): Milestone {
	if (i.hasRoot) return "root";
	if (i.hasFoothold || i.credsRecovered > 0) return "foothold";
	if (i.counts.candidate > 0 || i.counts.validated > 0) return "candidate_found";
	// More than a bare port scan's worth of investigation nodes = surface mapped.
	if (i.nodeCount > 3) return "surface_mapped";
	if (i.attemptCount > 0) return "recon";
	return "started";
}

export function buildRunSummary(input: RunSummaryInput): RunSummary {
	return {
		schema: 1,
		ts: new Date().toISOString(),
		reached: deriveMilestone(input),
		trustworthyValidated: Math.max(0, input.counts.validated - input.untrustedValidated),
		...input,
	};
}

/** Numeric rank of a milestone — for comparing runs (higher = further). */
export function milestoneRank(m: Milestone): number {
	return MILESTONE_ORDER.indexOf(m);
}
