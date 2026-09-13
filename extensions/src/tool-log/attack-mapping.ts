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
import { parseBaseTool } from "../shared/bash-command.js";

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

export function attackTagForCommand(command: string): AttackTag | undefined {
	const tool = parseBaseTool(command);
	if (!tool) {
		return undefined;
	}
	return TOOL_ATTACK_TAGS[tool.toLowerCase()];
}
