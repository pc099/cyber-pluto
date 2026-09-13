/**
 * Typed row shapes for the Layer 2 state schema (Architecture §4).
 * The schema is the contract (typescript-patterns skill): status and type
 * columns are string-literal unions here, not bare strings, so an illegal
 * value is a compile error at every call site, not just a runtime surprise.
 */

export type EngagementPhase = "recon" | "enum" | "vuln" | "exploit" | "post" | "report";

export interface TargetRow {
	id: number;
	label: string;
	host: string | null;
	scope_notes: string | null;
	phase: EngagementPhase;
	created_at: string;
}

export type NodeType =
	| "recon"
	| "investigate_port"
	| "service_enum"
	| "vuln_hypothesis"
	| "exploit_attempt"
	| "cross_service_hypothesis"
	| "dead_end";

export type NodeStatus = "active" | "deprioritized" | "dead_end" | "resolved";

export interface NodeRow {
	id: number;
	target_id: number;
	parent_id: number | null;
	node_type: NodeType;
	status: NodeStatus;
	label: string;
	priority: number;
	created_at: string;
	updated_at: string;
}

/**
 * The fact ledger (pluto-build invariant 3): a finding is born `candidate`
 * and only a Gate 1 validator (Session 4) may advance it to `validated`. A
 * version-string match alone can only ever produce `candidate`.
 */
export type FindingStatus = "candidate" | "validated" | "submitted" | "rejected";

export interface FindingRow {
	id: number;
	target_id: number;
	node_id: number | null;
	port: number | null;
	protocol: "tcp" | "udp" | null;
	service: string | null;
	product: string | null;
	version: string | null;
	honeypot_susp: 0 | 1;
	confidence: number | null;
	status: FindingStatus;
	created_at: string;
}

export type SecretType = "password" | "hash" | "key" | "token";

export interface CredentialRow {
	id: number;
	target_id: number;
	node_id: number | null;
	username: string | null;
	secret: string | null;
	secret_type: SecretType | null;
	source: string | null;
	scope: string | null;
	validated: 0 | 1;
	created_at: string;
}

export type AttemptOutcome = "success" | "failure" | "inconclusive";

/**
 * tactic/technique realize Architecture §5.4: every attempts row should
 * carry an ATT&CK tactic and, where applicable, technique ID alongside its
 * tool and command. Nullable because not every Pi tool call (e.g. `read`,
 * `edit`) maps onto an adversary technique — leave untagged rather than
 * guess a wrong tag (cybersecurity-modules: auditable in the terms a human
 * reviewer already thinks in, which a fabricated tag would undermine).
 */
export interface AttemptRow {
	id: number;
	target_id: number;
	node_id: number | null;
	tool: string;
	command: string;
	started_at: string;
	finished_at: string | null;
	outcome: AttemptOutcome | null;
	output_ref: string | null;
	reasoning_note: string | null;
	tactic: string | null;
	technique: string | null;
}

export interface ValidationRow {
	id: number;
	finding_id: number;
	validator: string;
	baseline_ref: string | null;
	attack_ref: string | null;
	diff_summary: string | null;
	passed: 0 | 1;
	validated_at: string;
}

export interface SubmissionRow {
	id: number;
	finding_id: number;
	program: string | null;
	approved_by: string;
	approved_at: string;
	submitted_at: string | null;
	platform_ref: string | null;
}

/** The moment a screenshot was captured (Architecture §2.3.1): after a payload
 * is submitted, when a new page state loads, when a CAPTCHA is suspected, or an
 * explicit manual capture. */
export type ScreenshotTrigger = "payload_submit" | "new_page" | "captcha_suspected" | "manual";

/**
 * The vision-pipeline evidence type (Architecture §2.3.1) — a captured
 * headless-browser screenshot, stored alongside findings. The image bytes live
 * as an evidence file (`path`); the row is the queryable record. `sha256` gives
 * exact-duplicate detection so the same view captured twice isn't re-analyzed.
 */
export interface ScreenshotRow {
	id: number;
	target_id: number;
	node_id: number | null;
	finding_id: number | null;
	url: string | null;
	trigger: ScreenshotTrigger;
	path: string;
	sha256: string | null;
	width: number | null;
	height: number | null;
	note: string | null;
	captured_at: string;
}
