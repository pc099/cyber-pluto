/**
 * Headless-browser screenshot capture (Architecture §2.3.1).
 *
 * Uses Chromium's built-in `--headless --screenshot` — no Puppeteer/Playwright
 * driver dependency. This keeps the vision pipeline the "scoped, buildable"
 * XBOW-style capture the reference calls for (a screenshot at an
 * exploitation-relevant moment fed to Claude's vision), rather than a
 * general-purpose live action-perception loop.
 *
 * Pure capture: this module shells out to Chromium and writes an evidence
 * file + returns its hash/dimensions. Recording the `screenshots` row and
 * feeding the image to the model is the extension's job (index.ts).
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const EVIDENCE_DIR = "evidence/screenshots";
const CAPTURE_TIMEOUT_MS = 45000;
const DEFAULT_WIDTH = 1280;
const DEFAULT_HEIGHT = 900;

export interface CaptureResult {
	relPath: string;
	absPath: string;
	sha256: string;
	width: number;
	height: number;
	bytes: number;
	mimeType: "image/png";
	base64: string;
}

export interface CaptureOptions {
	width?: number;
	height?: number;
	chromiumBin?: string;
	/** ms of virtual time to let the page settle/run JS before the shot. */
	settleMs?: number;
}

function chromiumBinary(opts: CaptureOptions): string {
	return opts.chromiumBin ?? process.env["PLUTO_CHROMIUM_BIN"] ?? "chromium";
}

/** Parse width/height out of a PNG's IHDR chunk (bytes 16..24). */
function pngDimensions(buf: Buffer): { width: number; height: number } {
	if (buf.length < 24 || buf.toString("ascii", 12, 16) !== "IHDR") {
		return { width: 0, height: 0 };
	}
	return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

export async function captureScreenshot(cwd: string, url: string, opts: CaptureOptions = {}): Promise<CaptureResult> {
	const width = opts.width ?? DEFAULT_WIDTH;
	const height = opts.height ?? DEFAULT_HEIGHT;
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	const relPath = join(EVIDENCE_DIR, `shot-${stamp}-${Math.random().toString(36).slice(2, 8)}.png`);
	const absPath = join(cwd, relPath);
	await mkdir(join(cwd, EVIDENCE_DIR), { recursive: true });

	const args = [
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		`--window-size=${width},${height}`,
		`--virtual-time-budget=${opts.settleMs ?? 2500}`,
		`--screenshot=${absPath}`,
		url,
	];

	await execFileAsync(chromiumBinary(opts), args, { cwd, timeout: CAPTURE_TIMEOUT_MS });

	const buf = await readFile(absPath);
	const { width: w, height: h } = pngDimensions(buf);
	return {
		relPath,
		absPath,
		sha256: createHash("sha256").update(buf).digest("hex"),
		width: w,
		height: h,
		bytes: buf.length,
		mimeType: "image/png",
		base64: buf.toString("base64"),
	};
}
