/**
 * A small, deliberately incomplete ATT&CK tag lookup for bash commands the
 * reasoning core runs, realizing Architecture §5.4 ("every row written to
 * attempts should carry an ATT&CK tactic and, where applicable, technique
 * ID"). Same philosophy as the §4.5 validator table: a starting reference
 * set that's easy to extend — a new row is a new mapping, not a redesign.
 *
 * Deliberately conservative: an unmapped or ambiguous command (curl, wget —
 * used for too many different things to tag confidently) is left untagged
 * rather than guessing, because a wrong ATT&CK tag is worse than no tag for
 * an audit trail meant to be trustworthy.
 */

export interface AttackTag {
	tactic: string;
	technique: string;
}

const TOOL_ATTACK_TAGS: Record<string, AttackTag> = {
	nmap: { tactic: "Reconnaissance", technique: "T1595" },
	masscan: { tactic: "Reconnaissance", technique: "T1595" },
	gobuster: { tactic: "Reconnaissance", technique: "T1595.003" },
	ffuf: { tactic: "Reconnaissance", technique: "T1595.003" },
	dirb: { tactic: "Reconnaissance", technique: "T1595.003" },
	feroxbuster: { tactic: "Reconnaissance", technique: "T1595.003" },
	nikto: { tactic: "Reconnaissance", technique: "T1595.002" },
	nuclei: { tactic: "Reconnaissance", technique: "T1595.002" },
	whatweb: { tactic: "Reconnaissance", technique: "T1595.002" },
	wpscan: { tactic: "Reconnaissance", technique: "T1595.002" },
	sqlmap: { tactic: "Initial Access", technique: "T1190" },
	msfconsole: { tactic: "Initial Access", technique: "T1190" },
	hydra: { tactic: "Credential Access", technique: "T1110" },
	medusa: { tactic: "Credential Access", technique: "T1110" },
	ncrack: { tactic: "Credential Access", technique: "T1110" },
	john: { tactic: "Credential Access", technique: "T1110.002" },
	hashcat: { tactic: "Credential Access", technique: "T1110.002" },
	enum4linux: { tactic: "Discovery", technique: "T1135" },
	smbclient: { tactic: "Discovery", technique: "T1135" },
	rpcclient: { tactic: "Discovery", technique: "T1135" },
};

/** Extracts the base command name from a bash invocation: env assignments
 * and a leading `sudo` are skipped, and any path prefix is stripped, so
 * `FOO=bar sudo /usr/bin/nmap -sV host` resolves to `nmap`. */
export function parseBaseTool(command: string): string | undefined {
	const tokens = command.trim().split(/\s+/).filter(Boolean);
	let i = 0;
	while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i] as string)) {
		i++;
	}
	if (tokens[i] === "sudo") {
		i++;
	}
	const raw = tokens[i];
	if (!raw) {
		return undefined;
	}
	return raw.split("/").pop();
}

export function attackTagForCommand(command: string): AttackTag | undefined {
	const tool = parseBaseTool(command);
	if (!tool) {
		return undefined;
	}
	return TOOL_ATTACK_TAGS[tool.toLowerCase()];
}
