/**
 * Foothold → privilege-escalation orchestration (autonomy fix, Decision 0006
 * follow-on). The board found Pluto could get a validated RCE foothold on its
 * own but then STALLED — it only escalated to root after the operator manually
 * named the privesc vectors (sudo/SUID/cron/kernel). This closes that gap: the
 * moment a Gate-1 RCE finding is validated, the harness seeds the standard
 * privilege-escalation checklist as HIGH-PRIORITY investigation nodes and tells
 * the agent to pivot — the "director" hints itself instead of waiting for a human.
 */
import type { Engagement } from "../state/engagement.js";

/** Validator classes that constitute a code-execution FOOTHOLD (vs a lesser
 * finding). A validated one triggers the privesc seed. */
export const FOOTHOLD_CLASSES = new Set(["file_write_rce", "command_injection", "arbitrary_file_write"]);

const MARK = "[privesc]";

/** The standard Linux privilege-escalation checklist, in impact/likelihood order.
 * Higher priority = investigate sooner. */
const PRIVESC_LEADS: ReadonlyArray<{ label: string; priority: number }> = [
	{ label: "Run automated enumeration (linpeas / linux-smart-enumeration `les` / pspy for cron) and triage its highest-signal finding FIRST", priority: 30 },
	{ label: "sudo -l — check this user's sudo rights (NOPASSWD entries → GTFOBins)", priority: 29 },
	{ label: "SUID/SGID binaries: `find / -perm -4000 -o -perm -2000 2>/dev/null` → GTFOBins escalation", priority: 28 },
	{ label: "Kernel exploit: `uname -a` → match version to known local-root (Dirty Pipe CVE-2022-0847 on 5.8–5.16; DirtyCow; pwnkit CVE-2021-4034 via pkexec)", priority: 28 },
	{ label: "Cron abuse: /etc/cron*, `crontab -l`, and any root-run script/dir that is world-writable (watch with pspy)", priority: 27 },
	{ label: "Writable sensitive files: /etc/passwd, /etc/shadow, /etc/cron.d, service configs, and group membership (/etc/group)", priority: 27 },
	{ label: "Linux capabilities: `getcap -r / 2>/dev/null` (cap_setuid, etc.)", priority: 26 },
	{ label: "Credential reuse: try any recovered credential against su/ssh/services; grep configs, history, and backups for plaintext passwords", priority: 26 },
	{ label: "Prove root minimally then STOP (capture the flags / show euid=0); clean up every planted artifact afterward", priority: 25 },
];

/**
 * Seed the privesc checklist under the engagement root, ONCE. Idempotent — a
 * second validated foothold won't duplicate the leads. Returns the number of
 * lead nodes created (0 if already seeded).
 */
export function seedPrivescLeads(engagement: Engagement): number {
	const already = engagement.repos.nodes.listByTarget(engagement.targetId).some((n) => n.label.startsWith(MARK));
	if (already) return 0;
	const parent = engagement.repos.nodes.create({
		targetId: engagement.targetId,
		parentId: engagement.rootNodeId,
		nodeType: "vuln_hypothesis",
		label: `${MARK} FOOTHOLD validated — now escalate to root (do NOT stop at the foothold)`,
		priority: 31,
	});
	for (const lead of PRIVESC_LEADS) {
		engagement.repos.nodes.create({
			targetId: engagement.targetId,
			parentId: parent.id,
			nodeType: "vuln_hypothesis",
			label: `${MARK} ${lead.label}`,
			priority: lead.priority,
		});
	}
	return PRIVESC_LEADS.length;
}

/** The directive appended to the validator result so the reasoning core is told,
 * in-band, to pivot to privesc (the tree seed is passive; this is active). */
export const PRIVESC_DIRECTIVE =
	"FOOTHOLD VALIDATED. Do NOT stop here — escalate to root. High-priority next steps are now in the investigation tree (list_investigation_nodes): run automated enumeration (linpeas/les/pspy), then work sudo -l, SUID/SGID, kernel exploits (match `uname -a` to Dirty Pipe/pwnkit/DirtyCow), writable cron/configs, and credential reuse. Prove root minimally, capture the flags, and clean up every planted artifact.";
