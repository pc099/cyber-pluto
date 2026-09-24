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
	// Newer tools added with the autonomy toolset — same conservative principle.
	wfuzz: { tactic: "Reconnaissance", technique: "T1595.003" },
	dirbuster: { tactic: "Reconnaissance", technique: "T1595.003" },
	cewl: { tactic: "Reconnaissance", technique: "T1595" }, // wordlist gen scraped from the target
	patator: { tactic: "Credential Access", technique: "T1110" },
	crowbar: { tactic: "Credential Access", technique: "T1110" },
	hashid: { tactic: "Credential Access", technique: "T1110.002" }, // hash identification for cracking
};

/**
 * Command-SIGNATURE tags for privilege-escalation activity that base-tool
 * lookup misses: enumeration scripts are run through an interpreter
 * (`sh linpeas.sh`, `curl … | bash`, `./pspy64`), so parseBaseTool sees `sh`/
 * `curl`/`pspy64`, not the script's purpose, and `sudo -l` loses its `sudo` to
 * the parser. Each entry is an UNAMBIGUOUS substring whose presence pins the
 * intent. Same conservative rule: only add a signature that means one thing.
 */
const SIGNATURE_ATTACK_TAGS: Array<{ re: RegExp; tag: AttackTag }> = [
	{ re: /\blinpeas\b/i, tag: { tactic: "Discovery", technique: "T1082" } }, // system-wide privesc enumeration
	{ re: /\blinenum\b/i, tag: { tactic: "Discovery", technique: "T1082" } },
	{ re: /\blse\.sh\b|linux-smart-enumeration/i, tag: { tactic: "Discovery", technique: "T1082" } },
	{ re: /\bpspy\d*\b/i, tag: { tactic: "Discovery", technique: "T1057" } }, // process/cron monitoring
	{ re: /\bgetcap\b/i, tag: { tactic: "Discovery", technique: "T1082" } }, // capability enumeration
	{ re: /\bfind\b[^\n]*-perm[^\n]*(4000|-4000|-u\+s|2000)/i, tag: { tactic: "Discovery", technique: "T1083" } }, // SUID/SGID search
	{ re: /\bsudo\s+-l\b/i, tag: { tactic: "Privilege Escalation", technique: "T1548.003" } }, // enumerate sudo rights
	{ re: /linux-exploit-suggester|\bles\.sh\b/i, tag: { tactic: "Privilege Escalation", technique: "T1068" } },
	{ re: /\b(dirtypipe|dirty[_-]?pipe|cve-2022-0847)\b/i, tag: { tactic: "Privilege Escalation", technique: "T1068" } },
	{ re: /\b(dirtycow|dirty[_-]?cow|cve-2016-5195)\b/i, tag: { tactic: "Privilege Escalation", technique: "T1068" } },
	{ re: /\b(pwnkit|cve-2021-4034)\b/i, tag: { tactic: "Privilege Escalation", technique: "T1068" } },
	{ re: /\bchmod\s+[ug]?\+?s\b|\bchmod\s+[0-7]?[4-7][0-7]{3}\b[^\n]*bash/i, tag: { tactic: "Privilege Escalation", technique: "T1548.001" } }, // set a SUID bit (payload)
];

export function attackTagForCommand(command: string): AttackTag | undefined {
	const tool = parseBaseTool(command);
	const byTool = tool ? TOOL_ATTACK_TAGS[tool.toLowerCase()] : undefined;
	if (byTool) {
		return byTool;
	}
	// Fall back to a purpose signature so interpreter-run privesc enumeration and
	// sudo/SUID/kernel-exploit activity are tagged rather than lost.
	for (const { re, tag } of SIGNATURE_ATTACK_TAGS) {
		if (re.test(command)) {
			return tag;
		}
	}
	return undefined;
}
