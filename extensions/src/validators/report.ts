/**
 * Shared building blocks for the Gate 1 validator library (§4.5). Every
 * validator, whatever the class, produces a `ValidationReport` and answers the
 * two required questions — a technical signal (it exists) and an impact
 * artifact (it matters) — via verifiable-step chaining (§3.5). Keeping these
 * types + HTTP primitives in one place lets the extension's gate glue
 * (record evidence → validations row → guarded promote/reject) be written once
 * and reused by every class.
 */

import { politeFetch } from "../shared/http-policy.js";

export const REQUEST_TIMEOUT_MS = 5000;
export const MAX_BODY_CHARS = 8000;

export interface CapturedExchange {
	label: string;
	requestUrl: string;
	payload: string;
	status: number;
	body: string;
	networkError?: string;
}

export interface VerifiableStep {
	name: string;
	passed: boolean;
	detail: string;
}

export interface ValidationReport {
	/** The class that ran, e.g. "command_injection" — becomes validations.validator. */
	validator: string;
	passed: boolean;
	technicalSignal: boolean;
	impactArtifact: boolean;
	diffSummary: string;
	baseline: CapturedExchange | null;
	attacks: CapturedExchange[];
	steps: VerifiableStep[];
}

/** A per-validation nonce so a reflected/echoed marker can't be coincidence. */
export function makeMarker(prefix = "PLUTO"): string {
	return `${prefix}${Math.random().toString(36).slice(2, 10).toUpperCase()}MK`;
}

export function buildUrl(endpoint: string, param: string, value: string): string {
	const url = new URL(endpoint);
	url.searchParams.set(param, value);
	return url.toString();
}

export async function probe(endpoint: string, param: string, label: string, value: string): Promise<CapturedExchange> {
	const requestUrl = buildUrl(endpoint, param, value);
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
	try {
		const res = await politeFetch(requestUrl, { signal: controller.signal });
		const body = (await res.text()).slice(0, MAX_BODY_CHARS);
		return { label, requestUrl, payload: value, status: res.status, body };
	} catch (err) {
		return {
			label,
			requestUrl,
			payload: value,
			status: 0,
			body: "",
			networkError: err instanceof Error ? err.message : String(err),
		};
	} finally {
		clearTimeout(timer);
	}
}

export function baselineOk(ex: CapturedExchange): boolean {
	return ex.networkError === undefined && ex.status > 0 && ex.status < 500;
}
