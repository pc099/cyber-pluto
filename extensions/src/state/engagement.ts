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
import { openStateDb } from "./db.js";
import { type FindingsRepo, createFindingsRepo } from "./findings-repo.js";
import { type NodesRepo, createNodesRepo } from "./nodes-repo.js";
import { type TargetsRepo, createTargetsRepo } from "./targets-repo.js";
import { type ValidationsRepo, createValidationsRepo } from "./validations-repo.js";

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
	};
}

let engagement: Engagement | undefined;

export function startEngagement(cwd: string): Engagement {
	if (engagement) {
		return engagement;
	}

	const db = openStateDb(cwd);
	const repos = {
		targets: createTargetsRepo(db),
		nodes: createNodesRepo(db),
		attempts: createAttemptsRepo(db),
		findings: createFindingsRepo(db),
		validations: createValidationsRepo(db),
	};

	const label = process.env["PLUTO_TARGET_LABEL"] ?? "ad-hoc";
	const target =
		repos.targets.findByLabel(label) ??
		repos.targets.create({ label, host: process.env["PLUTO_TARGET_HOST"] ?? "localhost" });
	const rootNode =
		repos.nodes.findRoot(target.id) ??
		repos.nodes.create({ targetId: target.id, nodeType: "recon", label: "session root" });

	engagement = { db, targetId: target.id, rootNodeId: rootNode.id, repos };
	return engagement;
}

export function getEngagement(): Engagement | undefined {
	return engagement;
}
