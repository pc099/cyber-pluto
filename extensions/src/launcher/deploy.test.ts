import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, symlinkSync, statSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { deployRuntime, validateRuntime } from "./deploy.js";

test("setup refuses conflicting canonical resource overrides before publication or provisioning", () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-setup-refusal-"));
	try {
		for (const key of ["PLUTO_UID", "PLUTO_RUN_DIR", "PLUTO_CONTROL_DIR", "PLUTO_ENGAGEMENTS_DIR", "PLUTO_KEYDIR"]) {
			const destination = join(root, "runtime");
			const override = join(root, "unprovisioned");
			const result = spawnSync("bash", [resolve("../sandbox/setup.sh"), destination], { env: { ...process.env, [key]: override }, encoding: "utf8" });
			assert.equal(result.status, 1);
			assert.match(result.stderr, new RegExp(`${key} must be`));
			assert.equal(existsSync(destination), false);
			assert.equal(existsSync(override), false);
		}
	} finally { rmSync(root, { recursive: true, force: true }); }
});

function fixture(): { root: string; source: string; destination: string; write: (path: string, text?: string) => void; close: () => void } {
	const root = mkdtempSync(join(tmpdir(), "pluto-deploy-"));
	chmodSync(root, 0o755);
	const source = join(root, "source"), destination = join(root, "runtime");
	const write = (path: string, text = "fixture\n"): void => { mkdirSync(join(source, path, ".."), { recursive: true }); writeFileSync(join(source, path), text); };
	for (const path of ["cyberpluto", "sandbox/run-sandboxed.sh", "runtime-skills/example/SKILL.md", "extensions/src/guard/index.ts", "extensions/dist/guard/index.js", "services/pluto_services/__init__.py", "services/requirements.txt", "services/.venv/pyvenv.cfg", "pi/pi/package.json"]) write(path);
	write(".pi/settings.json", JSON.stringify({ extensions: ["../extensions/src/guard/index.ts"], skills: ["../runtime-skills"] }));
	write("extensions/package.json", JSON.stringify({ dependencies: { fixture: "1" } }));
	write("extensions/node_modules/fixture/package.json", JSON.stringify({ dependencies: { nested: "1" } }));
	write("extensions/node_modules/fixture/index.js");
	write("extensions/node_modules/nested/package.json", "{}");
	write("extensions/node_modules/nested/index.js");
	write("extensions/node_modules/development-secret/index.js");
	write("pi/pi/packages/coding-agent/package.json", "{}");
	write("pi/pi/packages/coding-agent/dist/bundle/cli.js");
	mkdirSync(join(source, "extensions/node_modules/@earendil-works"), { recursive: true });
	symlinkSync("../../../pi/pi/packages/coding-agent", join(source, "extensions/node_modules/@earendil-works/pi-coding-agent"));
	mkdirSync(join(source, "services/.venv/bin"), { recursive: true });
	symlinkSync("/usr/bin/python3", join(source, "services/.venv/bin/python"));
	write("services/.venv/bin/sample", `#!${source}/services/.venv/bin/python\nprint('fixture')\n`);
	write("services/.venv/pyvenv.cfg", "home = /usr/bin\ninclude-system-site-packages = false\n");
	write(".env", "excluded-private-fixture"); write(".git/config"); write("engagements/history/evidence/proof"); write("extensions/src/ignored.test.ts");
	return { root, source, destination, write, close: () => rmSync(root, { recursive: true, force: true }) };
}

test("offline deployment includes recursive dependencies and profile, excludes secrets/history/dev packages, and preserves source", () => {
	const f = fixture();
	try {
		const before = statSync(join(f.source, ".env")).mode;
		const manifest = deployRuntime(f.source, f.destination, { verify: false });
		assert.ok(manifest.files.some(e => e.path === "extensions/node_modules/nested/index.js"));
		assert.equal(existsSync(join(f.destination, ".env")), false);
		assert.equal(existsSync(join(f.destination, ".git")), false);
		assert.equal(existsSync(join(f.destination, "engagements")), false);
		assert.equal(existsSync(join(f.destination, "extensions/node_modules/development-secret")), false);
		assert.equal(existsSync(join(f.destination, "extensions/src/ignored.test.ts")), false);
		assert.equal(readFileSync(join(f.source, ".env"), "utf8"), "excluded-private-fixture");
		assert.equal(statSync(join(f.source, ".env")).mode, before);
		assert.ok(readFileSync(join(f.destination, "services/.venv/bin/sample"), "utf8").startsWith(`#!${f.destination}/services/.venv/bin/python3\n`));
		assert.deepEqual(validateRuntime(f.destination), manifest);
	} finally { f.close(); }
});

test("deployment rejects escaping symlinks and leaves no published runtime", () => {
	const f = fixture();
	try {
		symlinkSync("/etc/passwd", join(f.source, "extensions/src/escape.ts"));
		assert.throws(() => deployRuntime(f.source, f.destination, { verify: false }), /symlink escape/);
		assert.equal(existsSync(f.destination), false);
	} finally { f.close(); }
});

test("deployment refuses absent dependency and configured profile escape", () => {
	const f = fixture();
	try {
		f.write("extensions/package.json", JSON.stringify({ dependencies: { missing: "1" } }));
		assert.throws(() => deployRuntime(f.source, f.destination, { verify: false }), /missing offline dependency/);
		f.write("extensions/package.json", "{}");
		f.write(".pi/settings.json", JSON.stringify({ extensions: ["/etc/passwd"] }));
		assert.throws(() => deployRuntime(f.source, f.destination, { verify: false }), /profile escapes/);
		assert.equal(existsSync(f.destination), false);
	} finally { f.close(); }
});

test("Python home/path configuration cannot retain a dependency on /root", () => {
	const f = fixture();
	try {
		f.write("services/.venv/pyvenv.cfg", "home = /root/private-python\n");
		assert.throws(() => deployRuntime(f.source, f.destination, { verify: false }), /system interpreter home/);
		f.write("services/.venv/pyvenv.cfg", "home = /usr/bin\n");
		f.write("services/.venv/lib/escape.pth", "/root/private-package\n");
		assert.throws(() => deployRuntime(f.source, f.destination, { verify: false }), /Python path escapes/);
		assert.equal(existsSync(f.destination), false);
	} finally { f.close(); }
});

test("existing destination is untouched and manifest detects changed or added files", () => {
	const f = fixture();
	try {
		deployRuntime(f.source, f.destination, { verify: false });
		assert.throws(() => deployRuntime(f.source, f.destination, { verify: false }), /destination exists/);
		writeFileSync(join(f.destination, "extra"), "unmanifested", { mode: 0o444 });
		assert.throws(() => validateRuntime(f.destination), /manifest does not match/);
		rmSync(join(f.destination, "extra"));
		chmodSync(join(f.destination, "extensions/dist/guard/index.js"), 0o644);
		writeFileSync(join(f.destination, "extensions/dist/guard/index.js"), "changed");
		assert.throws(() => validateRuntime(f.destination), /manifest does not match/);
	} finally { f.close(); }
});

test("runtime writable permissions and paths under /root are refused", () => {
	const f = fixture();
	try {
		assert.throws(() => deployRuntime(f.source, "/root/unsafe-runtime", { verify: false }), /outside \/root/);
		deployRuntime(f.source, f.destination, { verify: false });
		chmodSync(join(f.destination, "extensions/dist/guard/index.js"), 0o666);
		assert.throws(() => validateRuntime(f.destination), /not protected/);
	} finally { f.close(); }
});

test("wrapper refuses disabled or missing bubblewrap before command execution", () => {
	const root = mkdtempSync(join(tmpdir(), "pluto-wrapper-reject-"));
	try {
		const marker = join(root, "executed");
		const wrapper = resolve(import.meta.dirname, "../../../sandbox/run-sandboxed.sh");
		const disabled = spawnSync("/usr/bin/bash", [wrapper, root, "--", "/usr/bin/touch", marker], { encoding: "utf8", env: { PATH: "/usr/bin:/bin", PLUTO_BWRAP: "0" } });
		assert.equal(disabled.status, 1); assert.match(disabled.stderr, /bubblewrap must be enabled/);
		const missing = spawnSync("/usr/bin/bash", [wrapper, root, "--", "/usr/bin/touch", marker], { encoding: "utf8", env: { PATH: root } });
		assert.equal(missing.status, 1); assert.match(missing.stderr, /bubblewrap missing/);
		assert.equal(existsSync(marker), false);
	} finally { rmSync(root, { recursive: true, force: true }); }
});
