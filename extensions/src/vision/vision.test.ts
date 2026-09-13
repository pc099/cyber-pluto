/**
 * Vision-pipeline tests. Capture is exercised against a local file:// HTML
 * page (hermetic — no server/network), asserting a real PNG is produced with a
 * content hash and parsed dimensions, and that the screenshots evidence repo
 * records and reads back the row. Skips gracefully if no Chromium is present,
 * so the suite still runs in environments without a browser.
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { captureScreenshot } from "./capture.js";
import { openStateDb } from "../state/db.js";
import { createScreenshotsRepo } from "../state/screenshots-repo.js";
import { createTargetsRepo } from "../state/targets-repo.js";

function chromiumAvailable(): boolean {
	const bin = process.env["PLUTO_CHROMIUM_BIN"] ?? "chromium";
	try {
		execFileSync(bin, ["--version"], { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

test("screenshots repo records and reads back a screenshot row", () => {
	const cwd = mkdtempSync(join(tmpdir(), "pluto-vision-"));
	const db = openStateDb(cwd);
	try {
		const target = createTargetsRepo(db).create({ label: "vision-test" });
		const repo = createScreenshotsRepo(db);
		const row = repo.create({
			targetId: target.id,
			url: "http://127.0.0.1/x",
			trigger: "payload_submit",
			path: "evidence/screenshots/x.png",
			sha256: "deadbeef",
			width: 800,
			height: 600,
			note: "looking for an error banner",
		});
		assert.equal(row.trigger, "payload_submit");
		const back = repo.getById(row.id);
		assert.equal(back?.sha256, "deadbeef");
		assert.equal(back?.width, 800);
		assert.equal(repo.listByTarget(target.id).length, 1);
	} finally {
		db.close();
	}
});

test("captureScreenshot produces a real PNG with a hash and dimensions", async (t) => {
	if (!chromiumAvailable()) {
		t.skip("no chromium binary available");
		return;
	}
	const cwd = mkdtempSync(join(tmpdir(), "pluto-vision-cap-"));
	const html = join(cwd, "page.html");
	writeFileSync(html, "<html><body style='font-size:40px'>PLUTO VISION OK</body></html>");

	const result = await captureScreenshot(cwd, `file://${html}`, { width: 640, height: 480, settleMs: 500 });
	assert.match(result.relPath, /^evidence\/screenshots\/shot-.*\.png$/);
	assert.equal(result.mimeType, "image/png");
	assert.equal(result.width, 640);
	assert.equal(result.height, 480);
	assert.ok(result.bytes > 0, "screenshot should have bytes");
	assert.match(result.sha256, /^[0-9a-f]{64}$/);
	assert.ok(result.base64.length > 0);
});
