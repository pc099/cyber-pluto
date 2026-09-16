/**
 * capabilities: adaptive capability provisioning (the "harness adapts to what
 * it's facing" feature). When Pluto recognizes the engagement class — a raw
 * binary service, a crypto challenge, a pcap — it calls `provision_capability`
 * with the DOMAIN, and the harness installs that domain's pre-vetted toolset
 * (from the manifest whitelist) and surfaces its doctrine skill into context.
 *
 * Safety: the model chooses a domain, never a package. Only packages declared
 * in manifest.ts are ever installed, so this cannot be prompt-injected into
 * installing arbitrary software. Every provision is logged as an attempt.
 */
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import type { AgentToolResult, ExtensionAPI, ExtensionContext, SessionStartEvent } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { getEngagement, startEngagement } from "../state/engagement.js";
import { CAPABILITIES, findCapability } from "./manifest.js";

const execFileAsync = promisify(execFile);

async function run(cmd: string, cwd: string): Promise<{ ok: boolean; output: string }> {
	try {
		const { stdout, stderr } = await execFileAsync("bash", ["-lc", cmd], {
			cwd,
			timeout: 300000,
			maxBuffer: 8 * 1024 * 1024,
			env: { ...process.env, DEBIAN_FRONTEND: "noninteractive" },
		});
		return { ok: true, output: `${stdout}\n${stderr}`.trim() };
	} catch (err) {
		const e = err as { stdout?: string; stderr?: string; message?: string };
		return { ok: false, output: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message ?? ""}`.trim() };
	}
}

function logProvision(domain: string, summary: string): void {
	const engagement = getEngagement();
	if (!engagement) return;
	const attempt = engagement.repos.attempts.start({
		targetId: engagement.targetId,
		nodeId: engagement.rootNodeId,
		tool: "provision_capability",
		command: `provision:${domain}`,
	});
	engagement.repos.attempts.finish(attempt.id, { outcome: "success", reasoningNote: summary.slice(0, 500) });
}

export default function capabilitiesExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_e: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.registerTool({
		name: "list_capabilities",
		label: "List provisionable capabilities",
		description:
			"List the engagement-class capabilities Pluto can provision on demand (binary-exploitation, cryptography, forensics, web). Each shows what it's for and the signals that indicate it applies. Call this when a target doesn't fit your current toolset, then provision the matching one.",
		parameters: Type.Object({}),
		execute(): Promise<AgentToolResult<unknown>> {
			const lines = CAPABILITIES.map(
				(c) => `- ${c.domain}: ${c.description}\n    provision when: ${c.detect.join("; ")}`,
			).join("\n");
			return Promise.resolve({
				content: [{ type: "text", text: `Provisionable capabilities:\n${lines}\n\nProvision with provision_capability(domain).` }],
				details: { domains: CAPABILITIES.map((c) => c.domain) },
			});
		},
	});

	pi.registerTool({
		name: "provision_capability",
		label: "Provision a capability (install tools + load doctrine)",
		description:
			"Adapt the harness to the engagement class you're facing. Installs the domain's pre-vetted toolset and returns its doctrine. Use it the moment you identify the target type and find your current tools don't fit — e.g. a raw binary/networked-binary service => 'binary-exploitation', a cipher/RSA challenge => 'cryptography', a pcap/dump => 'forensics'. You choose the DOMAIN; only that domain's whitelisted tools are installed.",
		parameters: Type.Object({
			domain: Type.String({ description: "The capability domain: binary-exploitation | cryptography | forensics | web" }),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const cap = findCapability(params.domain);
			if (!cap) {
				const known = CAPABILITIES.map((c) => c.domain).join(", ");
				return {
					content: [{ type: "text", text: `Unknown capability '${params.domain}'. Provisionable domains: ${known}. (Only whitelisted domains can be provisioned.)` }],
					details: { unknown: params.domain },
				};
			}

			const steps: string[] = [];
			if (cap.apt.length > 0) {
				const r = await run(`apt-get install -y ${cap.apt.join(" ")}`, ctx.cwd);
				steps.push(`apt ${cap.apt.join(" ")}: ${r.ok ? "ok" : "FAILED"}`);
			}
			if (cap.pip.length > 0) {
				const r = await run(`pip install --break-system-packages -q ${cap.pip.join(" ")}`, ctx.cwd);
				steps.push(`pip ${cap.pip.join(" ")}: ${r.ok ? "ok" : "FAILED"}`);
			}
			const verify = await run(cap.verify, ctx.cwd);
			steps.push(`verify: ${verify.ok ? "READY" : "NOT READY"}`);

			let doctrine = "";
			if (cap.skill) {
				try {
					doctrine = await readFile(join(ctx.cwd, cap.skill), "utf8");
				} catch {
					doctrine = `(doctrine skill at ${cap.skill} could not be read)`;
				}
			}

			const summary = `capability '${cap.domain}': ${steps.join(" | ")}`;
			logProvision(cap.domain, summary);

			const body = [
				`Provisioned capability: ${cap.domain} — ${cap.description}`,
				steps.map((s) => `  ${s}`).join("\n"),
				doctrine ? `\n--- DOCTRINE (${cap.skill}) ---\n${doctrine}` : "\n(no doctrine skill for this domain — the tools are installed; apply standard method.)",
			].join("\n");

			return {
				content: [{ type: "text", text: body }],
				details: { domain: cap.domain, ready: verify.ok, steps },
			};
		},
	});
}
