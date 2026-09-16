/**
 * Profile-integrity test — the regression net for the single-harness model.
 *
 * Pluto's definition now lives in `.pi/settings.json` (loaded by Pi, not
 * assembled by bash). If a path there is wrong, an extension is removed, or the
 * JSON breaks, the WHOLE harness silently loses that capability at launch — the
 * exact class of bug that made list_capabilities vanish during development. This
 * test asserts the profile is valid and everything it declares actually exists
 * and is loadable, so a structural change can't quietly gut the harness.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PI_DIR = resolve(REPO, ".pi");

type Profile = { extensions?: string[]; skills?: string[]; defaultProvider?: string };

function profile(): Profile {
	const raw = readFileSync(resolve(PI_DIR, "settings.json"), "utf8");
	return JSON.parse(raw) as Profile; // throws (fails the test) if the JSON is broken
}

test("the harness profile is valid JSON and declares the full stack", () => {
	const p = profile();
	assert.ok(Array.isArray(p.extensions) && p.extensions.length >= 8, "profile must declare the extension stack");
	assert.ok(Array.isArray(p.skills) && p.skills.length >= 1, "profile must declare the runtime-skill catalog");
	assert.ok(p.defaultProvider, "profile must set a default provider");
});

test("every extension the profile declares exists and exports a default", () => {
	for (const rel of profile().extensions ?? []) {
		// paths in .pi/settings.json resolve relative to the .pi/ dir
		const abs = resolve(PI_DIR, rel);
		assert.ok(existsSync(abs), `profile extension missing on disk: ${rel} (${abs})`);
		const src = readFileSync(abs, "utf8");
		assert.ok(/export\s+default\s+function/.test(src), `profile extension has no default export (not a Pi extension): ${rel}`);
	}
});

test("every skill directory the profile declares exists", () => {
	for (const rel of profile().skills ?? []) {
		const abs = resolve(PI_DIR, rel);
		assert.ok(existsSync(abs) && statSync(abs).isDirectory(), `profile skill dir missing: ${rel} (${abs})`);
	}
});

test("the built launcher exists (cyberpluto shim depends on it)", () => {
	assert.ok(existsSync(resolve(REPO, "extensions/dist/launcher/index.js")), "launcher not built");
});
