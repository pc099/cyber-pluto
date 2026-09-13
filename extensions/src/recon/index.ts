/**
 * recon: the Layer 4 feedback loop (Architecture §2.2/§5.1) — execute,
 * observe, update state, decide next.
 *
 * "Execute" and "observe" are Pi's own bash tool and this extension's
 * tool_execution_end hook; "update state" is turning a parsed nmap scan
 * into real tree nodes and candidate findings (deterministically — the
 * reasoning core doesn't have to remember to report a fingerprint for it
 * to become a fact); "decide next" is the list_investigation_nodes tool
 * below, which lets the reasoning core consult the real priority-ordered
 * tree instead of only its own conversation memory.
 *
 * Each newly fingerprinted service gets an `investigate_port` node, with
 * two `vuln_hypothesis` children seeded per §5.1's per-service checklist:
 * the cheap default-credential/misconfig check at higher priority, the
 * CVE path at lower priority — so the reasoning core naturally works the
 * cheap check first without being told to every time.
 */
import type {
	AgentToolResult,
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
	ToolCallEvent,
	ToolExecutionEndEvent,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { parseBaseTool } from "../shared/bash-command.js";
import { getEngagement, startEngagement } from "../state/engagement.js";
import type { NodeRow } from "../state/types.js";
import { parseNmapServices } from "./nmap-parser.js";
import { checklistForService } from "./service-checklist.js";

const INVESTIGATE_PORT_PRIORITY = 5;
const CHECK_FIRST_PRIORITY = 10;
const CVE_PATH_PRIORITY = 1;

/** Fingerprint-only confidence: a banner/version string is a candidate
 * lead, never proof (backporting makes version strings unreliable —
 * Architecture §4.3) — kept deliberately modest rather than confident. */
const FINGERPRINT_CONFIDENCE = 0.5;

const pendingBashCommands = new Map<string, string>();

function extractResultText(result: unknown): string {
	if (!result || typeof result !== "object" || !("content" in result)) {
		return "";
	}
	const content = (result as { content: unknown }).content;
	if (!Array.isArray(content)) {
		return "";
	}
	return content
		.map((item) => (item && typeof item === "object" && typeof (item as { text?: unknown }).text === "string"
			? (item as { text: string }).text
			: ""))
		.join("\n");
}

function growTreeFromNmapOutput(output: string): void {
	const engagement = getEngagement();
	if (!engagement) {
		return;
	}
	const openServices = parseNmapServices(output).filter((svc) => svc.state === "open");
	for (const svc of openServices) {
		const portNode = engagement.repos.nodes.create({
			targetId: engagement.targetId,
			parentId: engagement.rootNodeId,
			nodeType: "investigate_port",
			label: `port ${svc.port}/${svc.protocol} ${svc.service}`,
			priority: INVESTIGATE_PORT_PRIORITY,
		});

		const checklist = checklistForService(svc.service);
		engagement.repos.nodes.create({
			targetId: engagement.targetId,
			parentId: portNode.id,
			nodeType: "vuln_hypothesis",
			label: checklist.checkFirst,
			priority: CHECK_FIRST_PRIORITY,
		});
		engagement.repos.nodes.create({
			targetId: engagement.targetId,
			parentId: portNode.id,
			nodeType: "vuln_hypothesis",
			label: checklist.cvePath,
			priority: CVE_PATH_PRIORITY,
		});

		engagement.repos.findings.create({
			targetId: engagement.targetId,
			nodeId: portNode.id,
			port: svc.port,
			protocol: svc.protocol,
			service: svc.service,
			product: svc.product,
			version: svc.version,
			confidence: FINGERPRINT_CONFIDENCE,
		});
	}
}

function formatNode(node: NodeRow): string {
	return `#${node.id} [${node.node_type}] (priority ${node.priority}) ${node.label}`;
}

export default function reconExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.on("tool_call", (event: ToolCallEvent) => {
		if (event.toolName === "bash" && "command" in event.input) {
			pendingBashCommands.set(event.toolCallId, String(event.input.command));
		}
	});

	pi.on("tool_execution_end", (event: ToolExecutionEndEvent) => {
		const command = pendingBashCommands.get(event.toolCallId);
		pendingBashCommands.delete(event.toolCallId);
		if (event.isError || !command) {
			return;
		}
		if (parseBaseTool(command) !== "nmap") {
			return;
		}
		growTreeFromNmapOutput(extractResultText(event.result));
	});

	pi.registerTool({
		name: "list_investigation_nodes",
		label: "List Investigation Nodes",
		description:
			"Lists this engagement's active investigation-tree nodes, highest priority first. Consult this to decide what to pursue next instead of relying only on conversation memory — cheap default-credential/misconfig checks are seeded above CVE-path checks for the same service.",
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, _signal, _onUpdate, _ctx): Promise<AgentToolResult<unknown>> {
			const engagement = getEngagement();
			if (!engagement) {
				return {
					content: [{ type: "text", text: "No engagement state DB is open yet." }],
					details: {},
				};
			}
			const nodes = engagement.repos.nodes.listActiveByTarget(engagement.targetId);
			const text = nodes.length === 0
				? "No active investigation nodes yet."
				: nodes.map(formatNode).join("\n");
			return { content: [{ type: "text", text }], details: {} };
		},
	});
}
