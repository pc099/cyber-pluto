/**
 * Disclosure gate for the Shodan intel tool (board Decision 0001).
 *
 * Shodan is different from every other tool: it never contacts the target, it
 * sends the target's IDENTIFIER to a THIRD PARTY (Shodan) and returns intel
 * about it. So the ordinary scope rule ("don't touch out-of-scope hosts") guards
 * the wrong thing — the risk here is *disclosing* an identifier to an outside
 * service. The gate is therefore: you may only look up an IP that is IN SCOPE
 * (an identifier you are authorized to investigate). Looking up an arbitrary
 * third-party IP is an out-of-scope disclosure and is refused.
 *
 * Fail-closed: if no scope is configured, nothing may be disclosed.
 *
 * Pure module (no I/O), so the gate is fully unit-testable.
 */

/** Parse a dotted-quad IPv4 into a uint32, or undefined if it isn't one. */
function ipv4ToInt(ip: string): number | undefined {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
	if (!m) return undefined;
	const octets = m.slice(1, 5).map(Number);
	if (octets.some((o) => o > 255)) return undefined;
	return octets.reduce((acc, o) => ((acc << 8) | o) >>> 0, 0) >>> 0;
}

/** Does `ip` fall within a `a.b.c.d/len` IPv4 CIDR? */
function ipInCidr(ip: string, cidr: string): boolean {
	const parts = cidr.split("/");
	const net = parts[0];
	if (!net) return false;
	const len = Number(parts[1]);
	if (!Number.isInteger(len) || len < 0 || len > 32) return false;
	const ipInt = ipv4ToInt(ip);
	const netInt = ipv4ToInt(net);
	if (ipInt === undefined || netInt === undefined) return false;
	if (len === 0) return true;
	const mask = (0xffffffff << (32 - len)) >>> 0;
	return (ipInt & mask) === (netInt & mask);
}

export interface DisclosureDecision {
	allowed: boolean;
	reason: string;
}

/**
 * May `ip` be disclosed to Shodan? Allowed only when it matches an entry in the
 * scope list — an exact host/IP match, or membership in an in-scope IPv4 CIDR.
 * `scopeCsv` is the launcher's PLUTO_SCOPE_HOSTS (comma/space-separated).
 */
export function mayDiscloseIp(ip: string, scopeCsv: string | undefined): DisclosureDecision {
	const target = ip.trim();
	if (!target) return { allowed: false, reason: "no IP given" };
	const entries = (scopeCsv ?? "")
		.split(/[,\s]+/)
		.map((s) => s.trim())
		.filter(Boolean);
	if (entries.length === 0) {
		return { allowed: false, reason: "no scope configured (PLUTO_SCOPE_HOSTS) — refusing to disclose any identifier to a third party" };
	}
	for (const entry of entries) {
		if (entry === target) return { allowed: true, reason: `${target} is an in-scope target` };
		if (entry.includes("/") && ipInCidr(target, entry)) {
			return { allowed: true, reason: `${target} is within in-scope range ${entry}` };
		}
	}
	return {
		allowed: false,
		reason: `${target} is NOT in scope (${entries.join(", ")}); disclosing an out-of-scope identifier to Shodan is refused`,
	};
}
