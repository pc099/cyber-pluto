/**
 * Reflected-XSS validator (§4.5). Deterministic, non-LLM — it confirms
 * EXECUTION, not mere reflection, by rendering the page in a headless browser:
 *   - technical signal: the injected script actually runs — proven by a
 *     payload that sets document.title to a per-validation nonce and then
 *     reading the post-render DOM (Chromium --dump-dom executes JS); the title
 *     equals the nonce only if the script executed (an escaped/encoded payload
 *     leaves the title unchanged).
 *   - impact artifact: it executes in the page's own document context (the
 *     victim's session origin), not the attacker's — which is exactly what a
 *     title change in the target page's rendered DOM demonstrates.
 * Reflection of the raw payload text is NOT accepted as proof; only execution.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { type ValidationReport, type VerifiableStep, buildUrl, makeMarker } from "./report.js";

const execFileAsync = promisify(execFile);
const RENDER_TIMEOUT_MS = 30000;

export interface XssTarget {
	endpoint: string;
	param: string;
	baselineValue: string;
}

function chromiumBin(): string {
	return process.env["PLUTO_CHROMIUM_BIN"] ?? "chromium";
}

async function dumpDom(url: string): Promise<string> {
	const args = ["--headless", "--no-sandbox", "--disable-gpu", "--virtual-time-budget=2000", "--dump-dom", url];
	const { stdout } = await execFileAsync(chromiumBin(), args, { timeout: RENDER_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 });
	return stdout;
}

function extractTitle(dom: string): string | null {
	const m = /<title[^>]*>([^<]*)<\/title>/i.exec(dom);
	return m ? (m[1] as string).trim() : null;
}

export async function validateXss(target: XssTarget): Promise<ValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks: ValidationReport["attacks"] = [];

	const marker = makeMarker("XSS");
	const payload = `"><script>document.title=${JSON.stringify(marker)}</script>`;
	const baselineUrl = buildUrl(target.endpoint, target.param, target.baselineValue);
	const attackUrl = buildUrl(target.endpoint, target.param, payload);

	let baselineTitle: string | null = null;
	let attackTitle: string | null = null;
	let networkError: string | undefined;
	try {
		baselineTitle = extractTitle(await dumpDom(baselineUrl));
		attackTitle = extractTitle(await dumpDom(attackUrl));
	} catch (err) {
		networkError = err instanceof Error ? err.message : String(err);
	}

	const baseline = {
		label: "baseline-dom",
		requestUrl: baselineUrl,
		payload: target.baselineValue,
		status: networkError ? 0 : 200,
		body: `title=${baselineTitle ?? "(none)"}`,
		...(networkError ? { networkError } : {}),
	};
	attacks.push({
		label: "xss-dom",
		requestUrl: attackUrl,
		payload,
		status: networkError ? 0 : 200,
		body: `title=${attackTitle ?? "(none)"}`,
		...(networkError ? { networkError } : {}),
	});

	steps.push({
		name: "page-rendered",
		passed: networkError === undefined,
		detail: networkError ? `headless render failed: ${networkError}` : "baseline and attack pages rendered in a headless browser",
	});

	const executed = networkError === undefined && attackTitle === marker && baselineTitle !== marker;
	steps.push({
		name: "injected-script-executed",
		passed: executed,
		detail: executed
			? `injected script set document.title to ${marker} in the rendered DOM — it executed (not merely reflected)`
			: "injected script did not execute (payload was escaped/encoded or not reflected into an executable context)",
	});
	steps.push({
		name: "executes-in-page-context",
		passed: executed,
		detail: executed ? "execution occurred in the target page's own document/origin context" : "no execution in page context",
	});

	const summary = executed
		? `Reproduced. Technical signal + impact: injected script executed in the page's DOM context (document.title became ${marker}).`
		: `NOT reproduced: injected script did not execute${networkError ? ` (render error: ${networkError})` : ""}.`;
	return { validator: "xss", passed: executed, technicalSignal: executed, impactArtifact: executed, diffSummary: summary, baseline, attacks, steps };
}
