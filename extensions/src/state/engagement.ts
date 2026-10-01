/**
 * Opens the Layer 2 state DB and bootstraps the target + root recon node,
 * shared by every extension that needs to read or write state (tool-log's
 * attempts recording, recon's tree-growing).
 *
 * Bootstrap is idempotent *through the database*, keyed on the target
 * label, not through an in-process singleton: Pi loads each `-e` extension
 * file in its own module realm, so tool-log and recon each get their own
 * copy of this module's state — a JS-level cache alone would (and, before
 * this fix, did) produce two separate targets for one engagement. Reusing
 * by label also happens to be the architecturally correct behavior anyway:
 * Layer 2 is "per-target memory" meant to persist across many Pi
 * invocations against the same target, not be recreated fresh each time.
 *
 * Real multi-target/multi-engagement selection (as opposed to always
 * reusing the one ad-hoc target) is Session 11's job (engagement
 * lifecycle), not this one.
 */
import type { DatabaseSync } from "node:sqlite";
import { type AttemptsRepo, createAttemptsRepo } from "./attempts-repo.js";
import { type CredentialsRepo, createCredentialsRepo } from "./credentials-repo.js";
import { openStateDb } from "./db.js";
import { type FindingsRepo, createFindingsRepo } from "./findings-repo.js";
import { type NodesRepo, createNodesRepo } from "./nodes-repo.js";
import { resolveSigner } from "./promotion-signer.js";
import { resolveVerifier } from "./promotion-verifier.js";
import { type ScreenshotsRepo, createScreenshotsRepo } from "./screenshots-repo.js";
import { type SubmissionsRepo, createSubmissionsRepo } from "./submissions-repo.js";
import { type TargetsRepo, createTargetsRepo } from "./targets-repo.js";
import { type ValidationsRepo, createValidationsRepo } from "./validations-repo.js";
import { getActiveBinding } from "./session-binding.js";

export interface Engagement {
	db: DatabaseSync;
	targetId: number;
	rootNodeId: number;
	repos: {
		targets: TargetsRepo;
		nodes: NodesRepo;
		attempts: AttemptsRepo;
		findings: FindingsRepo;
		validations: ValidationsRepo;
		screenshots: ScreenshotsRepo;
		credentials: CredentialsRepo;
		submissions: SubmissionsRepo;
	};
}

let engagement: Engagement | undefined;
let engagementIdentity: string | undefined;
let engagementCwd: string | undefined;

export function resetEngagement(): void {
	engagement?.db.close();
	engagement = undefined;
	engagementIdentity = undefined;
	engagementCwd = undefined;
}

export function startEngagement(cwd: string): Engagement {
	let binding;
	try { binding = getActiveBinding(cwd); }
	catch (error) { resetEngagement(); throw error; }
	const identity = JSON.stringify([binding.sessionId, process.env.PLUTO_DELEGATE_ID ?? "", binding.association]);
	if (engagementIdentity !== identity) resetEngagement();
	if (engagement) return engagement;

	const db = openStateDb(cwd);
	let repos: Engagement["repos"];
	try { repos = {
		targets: createTargetsRepo(db),
		nodes: createNodesRepo(db),
		attempts: createAttemptsRepo(db),
		findings: createFindingsRepo(db, { signer: resolveSigner(), verifier: resolveVerifier() }),
		validations: createValidationsRepo(db),
		screenshots: createScreenshotsRepo(db),
		credentials: createCredentialsRepo(db),
		submissions: createSubmissionsRepo(db),
	}; } catch (error) { db.close(); throw error; }

	const label = binding.association.label;
	const target =
		repos.targets.findByLabel(label) ??
		repos.targets.create({ label, host: binding.association.host });
	if (target.host?.toLowerCase() !== binding.association.host) {
		db.close();
		throw new Error("Engagement binding blocked: existing ledger target host differs from explicit binding");
	}
	const rootNode =
		repos.nodes.findRoot(target.id) ??
		repos.nodes.create({ targetId: target.id, nodeType: "recon", label: "session root" });

	engagement = { db, targetId: target.id, rootNodeId: rootNode.id, repos };
	engagementIdentity = identity;
	engagementCwd = cwd;
	return engagement;
}

export function getEngagement(): Engagement | undefined {
	if (engagement) {
		try {
			const binding = getActiveBinding(engagementCwd ?? process.cwd());
			const identity = JSON.stringify([binding.sessionId, process.env.PLUTO_DELEGATE_ID ?? "", binding.association]);
			if (identity !== engagementIdentity) resetEngagement();
		} catch (error) { resetEngagement(); throw error; }
	}
	return engagement;
}
