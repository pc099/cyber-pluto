/** First guard: startup exceptions alone do not block Pi's built-in tools. */
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { bindSession, getActiveBinding } from "../state/session-binding.js";
import { startEngagement, resetEngagement } from "../state/engagement.js";

export default function engagementBindingExtension(pi: ExtensionAPI): void {
	let startupFailure: string | undefined;
	const failure = (ctx: ExtensionContext): string | undefined => {
		if (startupFailure) return startupFailure;
		try { getActiveBinding(ctx.cwd); return undefined; }
		catch (e) { return e instanceof Error ? e.message : String(e); }
	};
	pi.on("session_start", (event, ctx) => {
		startupFailure = undefined;
		resetEngagement();
		delete process.env.PLUTO_ACTIVE_SESSION_FILE;
		delete process.env.PLUTO_ACTIVE_SESSION_ID;
		delete process.env.PLUTO_ACTIVE_BINDING_PATH;
		try {
			const binding = bindSession({ cwd: ctx.cwd, sessionFile: ctx.sessionManager.getSessionFile(), sessionId: ctx.sessionManager.getSessionId(), entries: ctx.sessionManager.getBranch(), reason: event.reason });
			startEngagement(ctx.cwd);
			if (ctx.sessionManager.getSessionFile()) pi.appendEntry("pluto-engagement-binding", binding);
		} catch (error) {
			startupFailure = error instanceof Error ? error.message : String(error);
			console.error(`[pluto/binding] ${startupFailure}`);
		}
	});
	pi.on("input", (_event, ctx) => {
		const reason = failure(ctx);
		if (!reason) return { action: "continue" };
		console.error(`[pluto/binding] ${reason}`);
		return { action: "handled" };
	});
	pi.on("tool_call", (_event, ctx) => {
		const reason = failure(ctx);
		return reason ? { block: true, reason } : undefined;
	});
	pi.registerCommand("binding", {
		description: "Pluto: diagnose session binding without modifying target state",
		handler: async (_args, ctx) => {
			const reason = failure(ctx);
			ctx.ui.notify(reason ?? JSON.stringify(getActiveBinding(ctx.cwd)), reason ? "warning" : "info");
		},
	});
}
