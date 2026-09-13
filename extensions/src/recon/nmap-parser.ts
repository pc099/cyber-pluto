/**
 * Deterministic parsing of nmap's default human-readable `-sV` output into
 * structured service rows. Deliberately not LLM-driven: turning raw tool
 * output into facts the state DB can index is the harness's job, not
 * something to trust the reasoning core to remember to report every time.
 *
 * Only handles the plain-text port-table lines nmap actually printed in
 * Pluto's own smoke tests (e.g. `22/tcp open  ssh  OpenSSH 10.0p2 ...`).
 * A real engagement running `nmap -oX -` for structured XML output would
 * parse far more reliably than this text heuristic — worth revisiting once
 * Pluto is choosing its own recon commands rather than the LLM freely
 * typing `nmap -sV host`, but that's a later refinement, not Session 3's.
 */

export interface ParsedNmapService {
	port: number;
	protocol: "tcp" | "udp";
	state: string;
	service: string;
	product: string | null;
	version: string | null;
}

const PORT_LINE_RE = /^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.+))?$/;

export function parseNmapServices(output: string): ParsedNmapService[] {
	const services: ParsedNmapService[] = [];
	for (const rawLine of output.split("\n")) {
		const match = PORT_LINE_RE.exec(rawLine.trim());
		if (!match) {
			continue;
		}
		const [, portStr, protocol, state, service, versionText] = match;
		const { product, version } = splitProductVersion(versionText);
		services.push({
			port: Number(portStr),
			protocol: protocol as "tcp" | "udp",
			state: state as string,
			service: service as string,
			product,
			version,
		});
	}
	return services;
}

/**
 * nmap's VERSION column has no machine-readable product/version boundary.
 * Heuristic: the product name rarely contains a digit, so the first token
 * with a digit starts the version — "OpenSSH 10.0p2 Debian 7+deb13u4
 * (protocol 2.0)" splits to product "OpenSSH", version "10.0p2 Debian
 * 7+deb13u4 (protocol 2.0)"; "Exim smtpd 4.98.2" splits to "Exim smtpd" /
 * "4.98.2". Good enough for a candidate fingerprint; not exact for every
 * possible nmap version string.
 */
function splitProductVersion(text: string | undefined): { product: string | null; version: string | null } {
	if (!text) {
		return { product: null, version: null };
	}
	const trimmed = text.trim();
	const tokens = trimmed.split(/\s+/);
	const versionIndex = tokens.findIndex((token) => /\d/.test(token));
	if (versionIndex === -1) {
		return { product: trimmed, version: null };
	}
	if (versionIndex === 0) {
		return { product: null, version: trimmed };
	}
	return {
		product: tokens.slice(0, versionIndex).join(" "),
		version: tokens.slice(versionIndex).join(" "),
	};
}
