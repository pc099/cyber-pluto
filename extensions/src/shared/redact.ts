/**
 * Secret redaction for the audit log.
 *
 * "Everything is logged" is a Pluto invariant, but "never log secrets in the
 * clear where avoidable" is an equal one (evidence minimization). tool-log
 * writes every tool call's input and result to logs/tool-invocations.jsonl —
 * which can carry a private key, an auth token, an `sshpass -p` password, or a
 * credential dumped in tool output. This masks the high-confidence secret
 * shapes before the line is written, and caps oversized output so a full file
 * or pcap dump doesn't bloat (and leak into) the log.
 *
 * This is defence in depth, not a guarantee — a bare password sitting in ASCII
 * output has no reliable shape. Full coverage (masking every RECORDED credential
 * value, and redacting evidence files) is a deeper follow-on; the state DB
 * already stores evidence by reference, not inline.
 */

const PATTERNS: Array<[RegExp, string]> = [
	// PEM private key blocks.
	[/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, "[REDACTED PRIVATE KEY]"],
	// Authorization headers (Bearer / Basic).
	[/(authorization"?\s*[:=]\s*"?\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]"],
	// password / secret / api_key / token assignments.
	[/((?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|token|private[_-]?key)"?\s*[:=]\s*"?)([^\s"',}]{3,})/gi, "$1[REDACTED]"],
	// sshpass -p <pw>.
	[/(sshpass\s+-p\s*"?)([^\s"']+)/gi, "$1[REDACTED]"],
	// curl/wget style -u user:pass  or  --user user:pass  (mask the pass only).
	[/((?:-u|--user[= ])\s*[^\s:'"]+):([^\s'"]+)/gi, "$1:[REDACTED]"],
	// AWS access key ids.
	[/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED AWS KEY]"],
];

const MAX_FIELD = 16_000; // per-line cap on logged tool output

/** Redact high-confidence secret shapes, and mask any explicitly-known secret
 * values, in a log line. Then cap the length so a large dump can't bloat the
 * audit log. `known` are exact secret strings (e.g. recovered credentials). */
export function redactSecrets(text: string, known: readonly string[] = []): string {
	let out = text;
	for (const [re, repl] of PATTERNS) out = out.replace(re, repl);
	for (const secret of known) {
		if (secret && secret.length >= 3) out = out.split(secret).join("[REDACTED]");
	}
	if (out.length > MAX_FIELD) {
		out = `${out.slice(0, MAX_FIELD)}…[+${out.length - MAX_FIELD} bytes truncated]`;
	}
	return out;
}
