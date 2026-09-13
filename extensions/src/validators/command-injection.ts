/**
 * Command-injection validator (§4.5). Deterministic, non-LLM.
 *   - technical signal: command output appears in the response that the
 *     application would not itself produce — proven by injecting `echo <nonce>`
 *     and finding the nonce echoed back (absent from the baseline).
 *   - impact artifact: the output reveals real host/environment detail
 *     confirming genuine execution — proven by `id`/`uname` output patterns.
 * Restraint: we inject a benign marker + read-only recon (`id`, `uname`); we do
 * not run anything that changes the target.
 */
import { type ValidationReport, type VerifiableStep, baselineOk, makeMarker, probe } from "./report.js";

export interface CommandInjectionTarget {
	endpoint: string;
	param: string;
	baselineValue: string;
}

// Shell metacharacters to break out of the intended command context.
const INJECTORS = (marker: string, cmd: string): string[] => [
	`; ${cmd}`,
	`| ${cmd}`,
	`& ${cmd}`,
	`$(${cmd})`,
	`\`${cmd}\``,
	`%0a${cmd}`,
];

const HOST_DETAIL = /uid=\d+\([a-z0-9_-]+\)|gid=\d+\(|Linux [\w.-]+ \d|Darwin |GNU\/Linux/i;

export async function validateCommandInjection(target: CommandInjectionTarget): Promise<ValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks = [] as Awaited<ReturnType<typeof probe>>[];

	const baseline = await probe(target.endpoint, target.param, "baseline", target.baselineValue);
	const okBaseline = baselineOk(baseline);
	steps.push({ name: "baseline-reachable", passed: okBaseline, detail: `baseline HTTP ${baseline.status}` });
	if (!okBaseline) {
		return report(false, false, false, baseline, attacks, steps, "baseline unreachable");
	}

	// Technical signal: echo a nonce and detect it in the response.
	const marker = makeMarker("CMDI");
	let echoed = false;
	for (const inj of INJECTORS(marker, `echo ${marker}`)) {
		const ex = await probe(target.endpoint, target.param, "echo-probe", `${target.baselineValue}${inj}`);
		attacks.push(ex);
		if (!baseline.body.includes(marker) && ex.body.includes(marker)) {
			echoed = true;
			break;
		}
	}
	steps.push({
		name: "command-output-echoed",
		passed: echoed,
		detail: echoed ? `injected 'echo ${marker}' output appeared in the response` : "no injected command output observed",
	});

	// Impact artifact: real host/env detail via id / uname (only if signal fired).
	let hostDetail = false;
	if (echoed) {
		for (const cmd of ["id", "uname -a"]) {
			for (const inj of INJECTORS(marker, cmd)) {
				const ex = await probe(target.endpoint, target.param, `impact-${cmd.split(" ")[0]}`, `${target.baselineValue}${inj}`);
				attacks.push(ex);
				if (HOST_DETAIL.test(ex.body) && !HOST_DETAIL.test(baseline.body)) {
					hostDetail = true;
					break;
				}
			}
			if (hostDetail) break;
		}
	}
	steps.push({
		name: "host-detail-revealed",
		passed: hostDetail,
		detail: hostDetail ? "id/uname output confirmed real command execution on the host" : "no host/environment detail revealed",
	});

	const passed = echoed && hostDetail;
	const summary = passed
		? `Reproduced. Technical signal: injected 'echo ${marker}' reflected in the response. Impact: id/uname output confirms real host execution.`
		: `NOT reproduced${echoed ? " (echo seen but no host detail)" : " (no injected command output)"}.`;
	return report(passed, echoed, hostDetail, baseline, attacks, steps, summary);
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
	return { validator: "command_injection", passed, technicalSignal, impactArtifact, diffSummary, baseline, attacks, steps };
}
