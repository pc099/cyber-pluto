/**
 * Outbound HTTP policy for bug-bounty compliance (Architecture §8): a
 * traffic-identification header and a request rate limit. Programs require you
 * to identify your traffic (e.g. `X-HackerOne-Research: <handle>`) and to
 * respect a rate; this centralizes both so every request Pluto's own code
 * makes (the Gate 1 validators) carries the header and is paced.
 *
 * Config via env (set by the cyberpluto launcher):
 *   PLUTO_TRAFFIC_ID   "Header-Name: value"  (e.g. "X-Bug-Bounty: chaitanya")
 *   PLUTO_RATE_LIMIT   requests/second (default: unlimited)
 *
 * NOTE: this governs Pluto's OWN fetches (validators). Traffic from bash tools
 * the reasoning core runs (curl/sqlmap/ffuf/…) is the LLM's responsibility —
 * the launcher briefs it to pass the same header + rate flags, and a future
 * proxy could enforce it universally. Unset env = no-op, so CTF runs are
 * unaffected.
 */

let lastRequestAt = 0;

function minIntervalMs(): number {
	const rate = Number(process.env["PLUTO_RATE_LIMIT"]);
	return Number.isFinite(rate) && rate > 0 ? 1000 / rate : 0;
}

function trafficHeader(): { name: string; value: string } | null {
	const raw = process.env["PLUTO_TRAFFIC_ID"];
	if (!raw) return null;
	const idx = raw.indexOf(":");
	if (idx <= 0) return null;
	return { name: raw.slice(0, idx).trim(), value: raw.slice(idx + 1).trim() };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** fetch() with the traffic-ID header injected and the rate limit applied. */
export async function politeFetch(url: string, init: RequestInit = {}): Promise<Response> {
	const gap = minIntervalMs();
	if (gap > 0) {
		const wait = lastRequestAt + gap - Date.now();
		if (wait > 0) await sleep(wait);
		lastRequestAt = Date.now();
	}
	const headers = new Headers(init.headers);
	const t = trafficHeader();
	if (t && !headers.has(t.name)) {
		headers.set(t.name, t.value);
	}
	return fetch(url, { ...init, headers });
}
