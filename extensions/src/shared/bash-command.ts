/** Extracts the base command name from a bash invocation: env assignments
 * and a leading `sudo` are skipped, and any path prefix is stripped, so
 * `FOO=bar sudo /usr/bin/nmap -sV host` resolves to `nmap`. Shared by
 * tool-log (ATT&CK tagging) and recon (deciding whether output is nmap's
 * to parse) since both need to know what a bash command is actually
 * running. */
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
