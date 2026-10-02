/** Root-side bounded access-token injection. Never forwards refresh credentials. */
import { closeSync, constants, fstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { assertProtectedRootParents } from "../state/promotion-sign-core.js";

export function injectCodexAccessToken(env: NodeJS.ProcessEnv, authPath: string, now = Date.now(), minimumValidityMs = 300_000): void {
	assertProtectedRootParents(authPath);
	if (realpathSync(authPath) !== resolve(authPath)) throw new Error("Sandbox authentication refuses aliased credential paths");
	let raw: unknown;
	const fd = openSync(authPath, constants.O_RDONLY | constants.O_NOFOLLOW);
	try {
		const stat = fstatSync(fd);
		if (!stat.isFile() || stat.uid !== 0 || (stat.mode & 0o077) !== 0) throw new Error("Sandbox authentication requires a root-owned private regular auth file");
		try { raw = JSON.parse(readFileSync(fd, "utf8")); }
		catch { throw new Error("Sandbox authentication cannot read stored credentials"); }
	} finally { closeSync(fd); }
	const credential = (raw as Record<string, unknown> | null)?.["openai-codex"] as { type?: unknown; access?: unknown; expires?: unknown } | undefined;
	if (credential?.type !== "oauth" || typeof credential.access !== "string" || !credential.access || typeof credential.expires !== "number" || !Number.isFinite(credential.expires)) {
		throw new Error("Sandbox openai-codex authentication requires an existing OAuth access token; authenticate as the operator first");
	}
	if (credential.expires <= now + minimumValidityMs) {
		throw new Error("Sandbox openai-codex access token is expired or near expiry; refresh as the operator before launching");
	}
	env.PLUTO_CODEX_ACCESS_TOKEN = credential.access;
	env.PLUTO_CODEX_ACCESS_EXPIRES = String(credential.expires);
}
