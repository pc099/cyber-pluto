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
	// Provider API keys / tokens by their distinctive prefixes (anthropic, openai,
	// deepseek, groq, google, github, slack, and generic sk-/xai-). These have no
	// "key=" assignment context, so the shape itself is the signal.
	[/\b(sk-ant-[A-Za-z0-9._-]{8,}|sk-[A-Za-z0-9]{16,}|xai-[A-Za-z0-9]{16,}|gsk_[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, "[REDACTED KEY]"],
];

/** Redact high-confidence secret shapes, and mask any explicitly-known secret
 * values (e.g. recovered credentials), in a string. Masking only — it does NOT
 * truncate, so a caller can run it over a serialized JSON line without breaking
 * the JSON (size-cap the oversized FIELD first with capField, then redact). */
export function redactSecrets(text: string, known: readonly string[] = []): string {
	let out = text;
	for (const [re, repl] of PATTERNS) out = out.replace(re, repl);
	for (const secret of known) {
		if (secret && secret.length >= 3) out = out.split(secret).join("[REDACTED]");
	}
	return out;
}

const MAX_FIELD = 16_000; // per-FIELD cap on logged tool output

/** Cap a single logged value's serialized size so a large dump (a full pcap,
 * a file read) can't bloat the audit log. Applied to the field BEFORE the entry
 * is serialized, so the resulting JSONL line stays valid — capping the whole
 * serialized line (as before) truncated mid-string and produced unparseable
 * records. Returns the value unchanged when small, or a truncation marker. */
export function capField(value: unknown, max: number = MAX_FIELD): unknown {
	let s: string;
	try {
		s = typeof value === "string" ? value : JSON.stringify(value);
	} catch {
		return value;
	}
	if (s === undefined || s.length <= max) return value;
	return `${s.slice(0, max)}…[+${s.length - max} bytes truncated]`;
}
