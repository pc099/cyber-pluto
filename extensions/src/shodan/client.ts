/**
 * Thin Shodan REST client (board Decision 0001: a per-vendor REST extension, not
 * an MCP bridge). Hits the host-intel endpoint and normalizes the response into
 * a typed shape. Result-style returns (a lookup miss / bad key / rate-limit is
 * an expected outcome, not an exception); only wraps the network call.
 *
 * SECURITY: every field here is THIRD-PARTY, ATTACKER-INFLUENCEABLE data (a
 * service banner is set by whoever runs the service). It is treated strictly as
 * data — recorded as candidate intel, never executed or acted on — and banners
 * are length-capped so a hostile/huge banner can't bloat state or the log.
 */

export interface ShodanService {
	port: number;
	transport: string;
	product?: string;
	version?: string;
	/** The service banner (capped). Untrusted attacker-controlled text. */
	banner?: string;
}

export interface ShodanHostIntel {
	ip: string;
	ports: number[];
	services: ShodanService[];
	vulns: string[];
	org?: string;
	os?: string;
}

export type ShodanResult =
	| { ok: true; intel: ShodanHostIntel }
	| { ok: false; error: string };

const MAX_BANNER = 2_000;
const DEFAULT_BASE = "https://api.shodan.io";

function cap(s: unknown, max = MAX_BANNER): string | undefined {
	if (typeof s !== "string" || s.length === 0) return undefined;
	return s.length <= max ? s : `${s.slice(0, max)}…[+${s.length - max} bytes]`;
}

function toStringArray(v: unknown): string[] {
	if (Array.isArray(v)) return v.map(String);
	if (v && typeof v === "object") return Object.keys(v as Record<string, unknown>);
	return [];
}

/** Look up host intel for `ip`. `base` defaults to the real API; tests point it
 * at a stub. Never throws — a failure becomes { ok:false }. */
export async function fetchShodanHost(
	ip: string,
	opts: { key: string; base?: string; timeoutMs?: number },
): Promise<ShodanResult> {
	const base = (opts.base ?? DEFAULT_BASE).replace(/\/$/, "");
	if (!opts.key) return { ok: false, error: "no SHODAN_API_KEY configured" };
	const url = `${base}/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(opts.key)}`;
	const ctrl = new AbortController();
	const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 15_000);
	try {
		const res = await fetch(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
		const text = await res.text();
		if (!res.ok) {
			// Shodan puts a human message in {error:...}; surface it, capped.
			let msg = `HTTP ${res.status}`;
			try {
				const j = JSON.parse(text) as { error?: string };
				if (j.error) msg += `: ${cap(j.error, 200)}`;
			} catch {
				/* non-JSON body */
			}
			return { ok: false, error: msg };
		}
		let raw: unknown;
		try {
			raw = JSON.parse(text);
		} catch {
			return { ok: false, error: "malformed JSON from Shodan" };
		}
		if (!raw || typeof raw !== "object") return { ok: false, error: "unexpected Shodan response shape" };
		const o = raw as Record<string, unknown>;
		const dataArr = Array.isArray(o.data) ? (o.data as Array<Record<string, unknown>>) : [];
		const services: ShodanService[] = dataArr
			.filter((d) => typeof d.port === "number")
			.map((d) => ({
				port: d.port as number,
				transport: typeof d.transport === "string" ? d.transport : "tcp",
				product: cap(d.product, 200),
				version: cap(d.version, 100),
				banner: cap(d.data),
			}));
		const ports = Array.isArray(o.ports) ? (o.ports as unknown[]).filter((p): p is number => typeof p === "number") : services.map((s) => s.port);
		return {
			ok: true,
			intel: {
				ip: typeof o.ip_str === "string" ? o.ip_str : ip,
				ports,
				services,
				vulns: toStringArray(o.vulns),
				org: cap(o.org, 200),
				os: cap(o.os, 100),
			},
		};
	} catch (err) {
		const e = err as { name?: string; message?: string };
		if (e.name === "AbortError") return { ok: false, error: "Shodan request timed out" };
		return { ok: false, error: `Shodan request failed: ${e.message ?? String(err)}` };
	} finally {
		clearTimeout(timer);
	}
}
