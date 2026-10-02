/** Use an env-only, bounded access token through Pi's existing provider API. */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function sandboxAuthExtension(pi: ExtensionAPI): void {
	if (process.env.PLUTO_SANDBOX_MODE !== "requested") return;
	const token = process.env.PLUTO_CODEX_ACCESS_TOKEN;
	if (!token) return; // API-key providers use their own supported env sources.
	const expires = Number(process.env.PLUTO_CODEX_ACCESS_EXPIRES);
	if (!Number.isFinite(expires) || expires <= Date.now()) throw new Error("Sandbox access token is expired or lacks an expiry");
	pi.registerProvider("openai-codex", { apiKey: "$PLUTO_CODEX_ACCESS_TOKEN" });
}
