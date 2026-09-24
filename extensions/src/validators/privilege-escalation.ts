/**
 * Privilege-escalation validator (Gate 1, §4.5). Makes ROOT a ledger fact.
 *
 * Before this, a foothold→root escalation was only ever LOG evidence: the
 * reasoning core said "I got root", the operator believed the transcript, and
 * nothing in the two-gate model actually reproduced it (run-3's root was
 * operator-directed and never Gate-1 validated). This validator closes that:
 * root is `validated` only when deterministic, non-LLM code reproduces it.
 *
 * Deterministic. Two questions, verifiable-step-chained, over an execution
 * channel the agent already holds (ssh session, reverse shell, webshell) —
 * supplied DECLARATIVELY as two command TEMPLATES (not closures, so they cross
 * the tool boundary): one that runs a probe as the CURRENT unprivileged user,
 * one that runs it THROUGH the escalation vector (sudo, a planted SUID bash, a
 * kernel-exploit shell, a cron payload).
 *
 *   - TECHNICAL SIGNAL: the escalated channel runs OUR nonce'd probe and returns
 *     `uid=0(root)`, while the baseline channel returns a non-zero uid. The
 *     nonce (echoed by the probe) proves the command actually executed and the
 *     output is not a canned banner.
 *   - IMPACT ARTIFACT: the escalated channel can READ a root-only file
 *     (`/etc/shadow` by default) that the baseline channel provably CANNOT —
 *     captured as the exit-status DIFFERENTIAL (baseline denied, escalated
 *     allowed), never the file CONTENT. This is what a spoofed template (e.g.
 *     `echo 'uid=0(root)'`) cannot fake: echoing a string does not let you read
 *     shadow, so the differential fails and the finding does not pass. It is
 *     also do-no-harm — we retain only the two exit codes, not the secret.
 *
 * SAFETY: read-only + `id`. Nothing is planted on the target, so there is no
 * cleanup and no residue (unlike file_write_rce). We start by confirming the
 * baseline is genuinely unprivileged; if it is already root (or already reads
 * shadow), there is no escalation to prove and the finding is rejected, not
 * over-claimed.
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { MAX_BODY_CHARS, type CapturedExchange, type ValidationReport, type VerifiableStep } from "./report.js";

/** Declarative, serializable execution channel (Decision 0005 C1 shape). Each
 * template must contain the literal `{probe}` placeholder, which the validator
 * substitutes with the exact shell probe to run over that channel. */
export interface PrivescTarget {
	/** Runs `{probe}` as the CURRENT unprivileged user. e.g.
	 * `sshpass -p www-data ssh www-data@10.0.0.5 {probe}` or
	 * `curl -s 'http://10.0.0.5/shell.php' --data-urlencode 'c={probe}'`. */
	baselineExecTemplate: string;
	/** Runs `{probe}` THROUGH the escalation vector. e.g.
	 * `sshpass -p www-data ssh www-data@10.0.0.5 sudo {probe}` or
	 * `... '/tmp/rootbash -p -c {probe}'`. */
	escalatedExecTemplate: string;
	/** Root-only file for the read differential. Default `/etc/shadow`. Only its
	 * READABILITY (exit code) is used — its content is never captured. */
	rootOnlyReadPath?: string;
	/** Per-exec timeout (ms). Default 15s — an escalation shell can be slow. */
	timeoutMs?: number;
}

const PLACEHOLDER = "{probe}";
const DEFAULT_TIMEOUT_MS = 15_000;

interface ExecOutcome {
	stdout: string;
	code: number | null;
}

/** Run a single templated command via bash -c, capturing stdout + exit code.
 * A non-zero exit is NOT an error here — it is signal (e.g. a denied read). */
function runTemplate(template: string, probe: string, timeoutMs: number): Promise<ExecOutcome> {
	const command = template.split(PLACEHOLDER).join(probe);
	return new Promise((resolve) => {
		execFile("bash", ["-c", command], { timeout: timeoutMs, maxBuffer: 1 << 20 }, (err, stdout) => {
			// exec's callback carries the exit code on err.code for a non-zero exit.
			const code = err && typeof (err as { code?: unknown }).code === "number" ? ((err as { code: number }).code) : err ? null : 0;
			resolve({ stdout: String(stdout ?? "").slice(0, MAX_BODY_CHARS), code });
		});
	});
}

function exchange(label: string, template: string, probe: string, out: ExecOutcome): CapturedExchange {
	return { label, requestUrl: template.split(PLACEHOLDER).join("<probe>"), payload: probe, status: out.code ?? 0, body: out.stdout };
}

/** uid=0 exactly — matches `uid=0(root)` but never `uid=1000(...)`. */
function isRoot(idOutput: string): boolean {
	return /\buid=0\(/.test(idOutput);
}

export async function validatePrivilegeEscalation(target: PrivescTarget): Promise<ValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks: CapturedExchange[] = [];
	const timeout = target.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const shadow = target.rootOnlyReadPath ?? "/etc/shadow";
	const nonce = `PLUTO_${randomBytes(6).toString("hex").toUpperCase()}`;

	// Guard: each template must actually carry the probe placeholder, or it can't
	// run our probe and any "root" it returns is meaningless.
	if (!target.baselineExecTemplate.includes(PLACEHOLDER) || !target.escalatedExecTemplate.includes(PLACEHOLDER)) {
		return {
			validator: "privilege_escalation",
			passed: false,
			technicalSignal: false,
			impactArtifact: false,
			diffSummary: `Both exec templates must contain the literal ${PLACEHOLDER} placeholder; cannot validate without running our own probe.`,
			baseline: null,
			attacks,
			steps: [{ name: "template-shape", passed: false, detail: `missing ${PLACEHOLDER} in a template` }],
		};
	}

	// The id probe echoes our nonce first so a canned banner can't masquerade as
	// real execution: a genuine run returns the nonce AND the real id line.
	const idProbe = `'echo ${nonce}; id'`;
	// The read probe sends the file to /dev/null and echoes ONLY the exit code —
	// the secret is never captured, only whether the read was permitted.
	const readProbe = `'cat ${shadow} >/dev/null 2>&1; echo ${nonce}_RC=$?'`;

	// 1. BASELINE must be genuinely unprivileged — else there is nothing to escalate.
	const baseId = await runTemplate(target.baselineExecTemplate, idProbe, timeout);
	const baseline = exchange("baseline-id", target.baselineExecTemplate, idProbe, baseId);
	const baseRanOurProbe = baseId.stdout.includes(nonce);
	const baseUnprivileged = baseRanOurProbe && !isRoot(baseId.stdout);
	steps.push({
		name: "baseline-unprivileged",
		passed: baseUnprivileged,
		detail: baseRanOurProbe
			? isRoot(baseId.stdout)
				? "baseline channel is ALREADY root — no escalation to prove"
				: "baseline confirmed non-root"
			: "baseline channel did not run our probe (nonce absent) — channel is not usable",
	});

	// 2. TECHNICAL SIGNAL — the escalated channel returns uid=0 for OUR probe.
	const escId = await runTemplate(target.escalatedExecTemplate, idProbe, timeout);
	attacks.push(exchange("escalated-id", target.escalatedExecTemplate, idProbe, escId));
	const escRanOurProbe = escId.stdout.includes(nonce);
	const technicalSignal = baseUnprivileged && escRanOurProbe && isRoot(escId.stdout);
	steps.push({
		name: "escalated-euid-root",
		passed: technicalSignal,
		detail: escRanOurProbe ? (isRoot(escId.stdout) ? "escalated channel returned uid=0(root)" : "escalated channel did NOT return uid=0") : "escalated channel did not run our probe (nonce absent)",
	});

	// 3. IMPACT ARTIFACT — root-only read differential (denied for baseline,
	//    allowed for escalated). Exit codes only; content never captured. This is
	//    what a template that merely echoes "uid=0" cannot fake.
	const baseRead = await runTemplate(target.baselineExecTemplate, readProbe, timeout);
	attacks.push(exchange("baseline-shadow-read", target.baselineExecTemplate, readProbe, baseRead));
	const escRead = await runTemplate(target.escalatedExecTemplate, readProbe, timeout);
	attacks.push(exchange("escalated-shadow-read", target.escalatedExecTemplate, readProbe, escRead));
	const rc = (out: ExecOutcome): number | null => {
		const m = out.stdout.match(new RegExp(`${nonce}_RC=(\\d+)`));
		return m ? Number(m[1]) : null;
	};
	const baseReadRc = rc(baseRead);
	const escReadRc = rc(escRead);
	// Baseline must be DENIED (non-zero, and it must have actually run) and the
	// escalated read must SUCCEED (rc 0). Both directions are required.
	const baselineDenied = baseReadRc !== null && baseReadRc !== 0;
	const escalatedAllowed = escReadRc === 0;
	const impactArtifact = baselineDenied && escalatedAllowed;
	steps.push({
		name: "root-only-read-differential",
		passed: impactArtifact,
		detail: `${shadow}: baseline rc=${baseReadRc ?? "n/a"} (must be non-zero/denied), escalated rc=${escReadRc ?? "n/a"} (must be 0/allowed)`,
	});

	// VERDICT: root is a fact only when BOTH the euid signal and the root-only
	// read differential reproduce. `passed` reflects reproduction; there is no
	// artifact and thus no cleanup coupling. No over-claim: a euid=0 with no
	// working read differential does NOT pass (it could be a spoofed banner).
	const passed = technicalSignal && impactArtifact;
	let summary: string;
	if (passed) {
		summary = `Privilege escalation to root reproduced: escalated channel is uid=0 AND read ${shadow} (rc 0) where the unprivileged baseline was denied (rc ${baseReadRc}). Content not retained.`;
	} else if (!baseUnprivileged) {
		summary = baseRanOurProbe ? `Baseline channel is already root — no escalation demonstrated.` : `Baseline channel unusable (probe did not run); cannot establish an unprivileged starting point.`;
	} else if (technicalSignal && !impactArtifact) {
		summary = `euid=0 was returned but the root-only read differential did NOT hold (baseline rc=${baseReadRc}, escalated rc=${escReadRc}); NOT accepting an unproven banner as root.`;
	} else {
		summary = `Not reproduced: escalated channel did not demonstrate root (uid/read differential failed).`;
	}

	return {
		validator: "privilege_escalation",
		passed,
		technicalSignal,
		impactArtifact,
		diffSummary: summary,
		baseline,
		attacks,
		steps,
	};
}
