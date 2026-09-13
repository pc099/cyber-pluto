/**
 * vision: the §2.3.1 screenshot-to-vision pipeline as a custom Pi extension.
 *
 * Pi has no native live screenshot-to-vision loop (§2.3.1), so this adds one:
 * a `capture_and_view` tool the reasoning core calls at exploitation-relevant
 * moments (after submitting a payload, when a new page state loads, when a
 * CAPTCHA is suspected). It drives a headless browser to screenshot the URL,
 * records the shot as a `screenshots` evidence row (the new §2.3.1 evidence
 * type), and returns the image as vision content so Claude actually sees and
 * interprets the rendered page — not just its HTML.
 *
 * Because it is a normal tool call, the capture passes through the red-lines
 * gate like any other: the URL's host is scope-checked, so a screenshot of an
 * out-of-scope target is blocked pre-execution with no extra wiring.
 */
import type {
	AgentToolResult,
	ExtensionAPI,
	ExtensionContext,
	SessionStartEvent,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { getEngagement, startEngagement } from "../state/engagement.js";
import type { ScreenshotTrigger } from "../state/types.js";
import { captureScreenshot } from "./capture.js";

const TRIGGERS: ScreenshotTrigger[] = ["payload_submit", "new_page", "captcha_suspected", "manual"];

export default function visionExtension(pi: ExtensionAPI): void {
	pi.on("session_start", (_event: SessionStartEvent, ctx: ExtensionContext) => {
		startEngagement(ctx.cwd);
	});

	pi.registerTool({
		name: "capture_and_view",
		label: "Capture & View (Vision)",
		description:
			"Take a headless-browser screenshot of a URL and SEE the rendered page (not just its HTML). Use at exploitation-relevant moments — after submitting a payload (encode it in the URL query string), when a new page state loads, or when a CAPTCHA/pop-up is suspected. The screenshot is stored as evidence and returned as an image for you to interpret.",
		parameters: Type.Object({
			url: Type.String({ description: "Full URL to render, e.g. http://127.0.0.1:8888/item?id=1" }),
			reason: Type.Optional(
				Type.String({ description: "One of: payload_submit | new_page | captcha_suspected | manual" }),
			),
			note: Type.Optional(Type.String({ description: "What you're looking for in this capture" })),
			finding_id: Type.Optional(Type.Number({ description: "Associate the screenshot with a finding, if any" })),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx): Promise<AgentToolResult<unknown>> {
			const engagement = getEngagement();
			const trigger: ScreenshotTrigger = TRIGGERS.includes(params.reason as ScreenshotTrigger)
				? (params.reason as ScreenshotTrigger)
				: "manual";

			let capture;
			try {
				capture = await captureScreenshot(ctx.cwd, params.url);
			} catch (err) {
				return {
					content: [
						{
							type: "text",
							text: `Screenshot capture failed for ${params.url}: ${err instanceof Error ? err.message : String(err)}`,
						},
					],
					details: {},
				};
			}

			let screenshotId: number | undefined;
			if (engagement) {
				const row = engagement.repos.screenshots.create({
					targetId: engagement.targetId,
					nodeId: engagement.rootNodeId,
					findingId: params.finding_id ?? null,
					url: params.url,
					trigger,
					path: capture.relPath,
					sha256: capture.sha256,
					width: capture.width,
					height: capture.height,
					note: params.note ?? null,
				});
				screenshotId = row.id;
			}

			return {
				content: [
					{ type: "image", data: capture.base64, mimeType: capture.mimeType },
					{
						type: "text",
						text:
							`Screenshot of ${params.url} (${capture.width}x${capture.height}, ${capture.bytes} bytes)` +
							`${screenshotId ? `, recorded as screenshot #${screenshotId}` : ""}` +
							`, evidence: ${capture.relPath}. Interpret what the rendered page shows.`,
					},
				],
				details: { screenshotId, sha256: capture.sha256, path: capture.relPath },
			};
		},
	});
}
