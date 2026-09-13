/**
 * IDOR / broken-access-control validator (§4.5). Deterministic, non-LLM.
 *   - technical signal: DIFFERENTIAL ACCESS — the same request made as one
 *     identity reaches another owner's object. Proven by comparing your own
 *     resource against another's with your identity: a 200 on the other, with
 *     content that differs from your own.
 *   - impact artifact: the response contains ANOTHER user's actual data, not
 *     just a 200 — proven by the differing, substantial body.
 * Guard against false positives: the resource must be access-controlled at
 * all — an unauthenticated request to the other object must be DENIED. If it
 * is public (unauth also 200), that is not IDOR and the validator rejects.
 */
import type { CapturedExchange, ValidationReport, VerifiableStep } from "./report.js";

const TIMEOUT_MS = 5000;
const MIN_BODY = 8; // "substantial" — not an empty/trivial response

export interface IdorTarget {
	/** URL of a resource that belongs to YOUR identity (the baseline). */
	ownUrl: string;
	/** URL of a resource that belongs to ANOTHER identity (the attack). */
	otherUrl: string;
	/** Identity header(s) — e.g. { Cookie: "session=..." }. */
	headers?: Record<string, string>;
}

async function fetchCapture(label: string, url: string, headers?: Record<string, string>): Promise<CapturedExchange> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
	try {
		const res = await fetch(url, { headers, signal: controller.signal, redirect: "manual" });
		const body = Buffer.from(await res.arrayBuffer()).toString("latin1").slice(0, 8000);
		return { label, requestUrl: url, payload: JSON.stringify(headers ?? {}), status: res.status, body };
	} catch (err) {
		return { label, requestUrl: url, payload: "", status: 0, body: "", networkError: err instanceof Error ? err.message : String(err) };
	} finally {
		clearTimeout(timer);
	}
}

export async function validateIdor(target: IdorTarget): Promise<ValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks: CapturedExchange[] = [];

	const baseline = await fetchCapture("own-resource", target.ownUrl, target.headers);
	const ownOk = baseline.status === 200;
	steps.push({ name: "own-resource-accessible", passed: ownOk, detail: `own resource HTTP ${baseline.status}` });

	const other = await fetchCapture("other-resource", target.otherUrl, target.headers);
	attacks.push(other);
	const otherOk = other.status === 200;
	steps.push({ name: "cross-object-200", passed: otherOk, detail: `another owner's resource HTTP ${other.status}` });

	const differs = ownOk && otherOk && other.body !== baseline.body && other.body.length >= MIN_BODY;
	steps.push({
		name: "differential-access",
		passed: differs,
		detail: differs
			? "same identity, another object reference — returned different, substantial data (another owner's)"
			: "no differential: other resource matched own, was empty, or was not reachable",
	});

	// Guard: the resource must be access-controlled, else it's public, not IDOR.
	const unauth = await fetchCapture("other-resource-unauth", target.otherUrl);
	attacks.push(unauth);
	const accessControlled = unauth.status === 401 || unauth.status === 403 || unauth.status === 302;
	steps.push({
		name: "access-controlled",
		passed: accessControlled,
		detail: accessControlled
			? `unauthenticated request denied (HTTP ${unauth.status}) — the object is protected, so cross-access is a real IDOR`
			: `unauthenticated request returned HTTP ${unauth.status} — resource may be public, not an IDOR`,
	});

	const passed = differs && accessControlled;
	const summary = passed
		? "Reproduced. Differential access: the same identity reached another owner's object (200, different substantial data), while an unauthenticated request is denied — a genuine IDOR/broken access control."
		: `NOT reproduced${!differs ? " (no differential access to another owner's data)" : " (resource appears public, not access-controlled)"}.`;
	return {
		validator: "idor",
		passed,
		technicalSignal: differs,
		impactArtifact: differs,
		diffSummary: summary,
		baseline,
		attacks,
		steps,
	};
}
