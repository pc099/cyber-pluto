/** Offline, allowlisted deployment. Never bind or mutate the development tree. */
import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, realpathSync, readFileSync, writeFileSync, mkdirSync, readdirSync, copyFileSync, symlinkSync, readlinkSync, chmodSync, chownSync, renameSync, rmSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep, isAbsolute } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export interface RuntimeManifest {
	schema: 1;
	files: { path: string; sha256: string }[];
	symlinks: { path: string; target: string }[];
}
interface Package { name?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; }
const MANIFEST = "runtime-manifest.json";
const excluded = (name: string): boolean => name === ".git" || name === ".npmrc" || name.startsWith(".yarnrc") || name.startsWith(".env") || name === "__pycache__" || name.endsWith(".pyc") || name.endsWith(".test.ts") || name.endsWith(".test.js") || name.endsWith(".test.js.map") || name.endsWith(".test.d.ts");
const inside = (root: string, path: string): boolean => path === root || path.startsWith(`${root}${sep}`);
const digest = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");
function systemPython(path: string): boolean {
	return /^\/(usr\/bin|usr\/local\/bin)\/python[0-9.]*$/.test(path);
}
function relativeEntry(path: string): void {
	if (!path || isAbsolute(path) || path.split(/[\\/]/).some(p => p === ".." || p === "." || !p)) throw new Error(`unsafe manifest path: ${path}`);
}
function safeRoot(root: string): void {
	if (root === "/" || inside("/root", root) || /\s/.test(root)) throw new Error("runtime must be outside /root and have no whitespace");
	for (let path = root; path !== "/"; path = dirname(path)) {
		if (!existsSync(path)) continue;
		const s = lstatSync(path);
		const protectedStickyParent = path !== root && Boolean(s.mode & 0o1000);
		if (s.isSymbolicLink() || !s.isDirectory() || s.uid !== 0 || (s.mode & 0o055) !== 0o055 || ((s.mode & 0o022) && !protectedStickyParent)) throw new Error(`unsafe runtime ancestor: ${path}`);
	}
}
function runtimeEntries(root: string): RuntimeManifest {
	const manifest: RuntimeManifest = { schema: 1, files: [], symlinks: [] };
	function walk(path: string): void {
		const s = lstatSync(path);
		if (s.uid !== 0 || (!s.isSymbolicLink() && (s.mode & 0o022))) throw new Error(`runtime is not protected: ${path}`);
		if (s.isSymbolicLink()) {
			const target = readlinkSync(path), actual = realpathSync(path);
			if (!inside(root, actual) && !(inside(join(root, "services/.venv/bin"), path) && systemPython(actual))) throw new Error(`runtime symlink escapes: ${path}`);
			if (!inside(root, actual)) {
				safeRoot(dirname(actual));
				const interpreter = lstatSync(actual);
				if (!interpreter.isFile() || interpreter.uid !== 0 || (interpreter.mode & 0o022) || (interpreter.mode & 0o055) !== 0o055) throw new Error("system Python interpreter is not protected/readable");
			}
			manifest.symlinks.push({ path: relative(root, path), target });
		} else if (s.isDirectory()) {
			if ((s.mode & 0o055) !== 0o055) throw new Error(`runtime directory is not traversable: ${path}`);
			for (const name of readdirSync(path).sort()) walk(join(path, name));
		} else if (s.isFile()) {
			if ((s.mode & 0o044) !== 0o044) throw new Error(`runtime file is not readable: ${path}`);
			if (path !== join(root, MANIFEST)) manifest.files.push({ path: relative(root, path), sha256: digest(path) });
		} else throw new Error(`unsupported runtime entry: ${path}`);
	}
	walk(root);
	return manifest;
}
/** Validate closure, immutable ownership and hashes, including extra-file refusal. */
export function validateRuntime(root: string): RuntimeManifest {
	root = resolve(root); safeRoot(root);
	const declared = JSON.parse(readFileSync(join(root, MANIFEST), "utf8")) as RuntimeManifest;
	if (declared.schema !== 1 || !Array.isArray(declared.files) || !Array.isArray(declared.symlinks)) throw new Error("invalid runtime manifest");
	for (const entry of [...declared.files, ...declared.symlinks]) relativeEntry(entry.path);
	const actual = runtimeEntries(root);
	if (JSON.stringify(declared) !== JSON.stringify(actual)) throw new Error("runtime manifest does not match protected files/symlinks");
	const profile = JSON.parse(readFileSync(join(root, ".pi/settings.json"), "utf8")) as { extensions?: string[]; skills?: string[] };
	for (const entry of [...(profile.extensions ?? []), ...(profile.skills ?? [])]) {
		const path = realpathSync(resolve(root, ".pi", entry));
		if (!inside(root, path)) throw new Error("configured profile escapes runtime");
	}
	return declared;
}

/** Stage an independent runtime and atomically publish at an absent destination. */
export function deployRuntime(source: string, destination: string, options: { verify?: boolean } = {}): RuntimeManifest {
	if (process.getuid?.() !== 0) throw new Error("deployment requires root ownership");
	source = realpathSync(source); destination = resolve(destination); safeRoot(destination);
	if (inside(source, destination) || inside(destination, source)) throw new Error("runtime and source must be separate");
	if (existsSync(destination) || (() => { try { lstatSync(destination); return true; } catch { return false; } })()) throw new Error("deployment destination exists; choose an absent versioned path");
	mkdirSync(dirname(destination), { recursive: true, mode: 0o755 }); safeRoot(dirname(destination));
	const stage = join(dirname(destination), `.${basename(destination)}.staging-${randomUUID()}`);
	mkdirSync(stage, { mode: 0o755 });
	const copied = new Set<string>(), packages = new Set<string>();
	function copy(path: string): void {
		if (!inside(source, path)) throw new Error(`deployment source escape: ${path}`);
		if (copied.has(path)) return;
		copied.add(path);
		const dest = join(stage, relative(source, path));
		const s = lstatSync(path);
		mkdirSync(dirname(dest), { recursive: true, mode: 0o755 });
		if (s.isSymbolicLink()) {
			const target = realpathSync(path);
			if (inside(source, target)) symlinkSync(relative(dirname(dest), join(stage, relative(source, target))), dest);
			else if (inside(join(source, "services/.venv/bin"), path) && systemPython(target)) symlinkSync(target, dest);
			else throw new Error(`deployment symlink escape: ${path}`);
		} else if (s.isDirectory()) {
			mkdirSync(dest, { recursive: true, mode: 0o755 });
			for (const name of readdirSync(path).sort()) if (!excluded(name) && name !== "node_modules") copy(join(path, name));
		} else if (s.isFile()) {
			copyFileSync(path, dest);
			// venv executable shebangs and cfg record the original absolute checkout.
			if (inside(join(source, "services/.venv/bin"), path)) {
				const bytes = readFileSync(dest);
				if (!bytes.includes(0)) {
					const text = bytes.toString().replaceAll(join(source, "services/.venv"), join(destination, "services/.venv"));
					writeFileSync(dest, text.replace(/^#![^\n]*\/services\/\.venv\/bin\/python[^\n]*\n/, `#!${destination}/services/.venv/bin/python3\n`));
				}
			} else if (relative(source, path) === "services/.venv/pyvenv.cfg") {
				const config = readFileSync(dest, "utf8");
				const home = /^home\s*=\s*(.+)$/m.exec(config)?.[1]?.trim();
				if (home !== "/usr/bin" && home !== "/usr/local/bin") throw new Error("venv requires a system interpreter home outside /root");
				writeFileSync(dest, config.split("\n").filter(line => !line.startsWith("command = ")).join("\n"));
			}
			if (path.endsWith(".pth") && readFileSync(dest, "utf8").includes("/root/")) throw new Error(`Python path escapes to /root: ${path}`);
			chmodSync(dest, s.mode & 0o111 ? 0o555 : 0o444); chownSync(dest, 0, 0);
		} else throw new Error(`unsupported deployment entry: ${path}`);
	}
	function findPackage(name: string, from: string): string | undefined {
		for (let at = from; inside(source, at); at = dirname(at)) {
			const candidate = join(at, "node_modules", name);
			if (existsSync(join(candidate, "package.json"))) return candidate;
			if (at === source) break;
		}
		return undefined;
	}
	function packageClosure(path: string): void {
		if (lstatSync(path).isSymbolicLink()) { copy(path); path = realpathSync(path); }
		if (!inside(source, path)) throw new Error("dependency package escapes source");
		if (packages.has(path)) return;
		packages.add(path);
		const pkg = JSON.parse(readFileSync(join(path, "package.json"), "utf8")) as Package;
		if (inside(join(source, "pi/pi/packages"), path)) {
			for (const name of ["package.json", "dist", "src", "docs", "README.md", "CHANGELOG.md"]) if (existsSync(join(path, name))) copy(join(path, name));
		} else copy(path);
		for (const name of new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.optionalDependencies ?? {})])) {
			const found = findPackage(name, path);
			if (found) packageClosure(found);
			else if (!(name in (pkg.optionalDependencies ?? {}))) throw new Error(`missing offline dependency ${name}`);
		}
	}
	try {
		for (const path of ["cyberpluto", ".pi/settings.json", "runtime-skills", "extensions/package.json", "extensions/src", "extensions/dist", "sandbox", "services/pluto_services", "services/.venv", "services/requirements.txt", "pi/pi/package.json"]) copy(join(source, path));
		const ext = JSON.parse(readFileSync(join(source, "extensions/package.json"), "utf8")) as Package;
		for (const name of [...Object.keys(ext.dependencies ?? {}), "@earendil-works/pi-coding-agent"]) {
			const found = findPackage(name, join(source, "extensions"));
			if (!found) throw new Error(`missing offline dependency ${name}`);
			packageClosure(found);
		}
		const manifest = runtimeEntries(stage);
		writeFileSync(join(stage, MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o444 });
		validateRuntime(stage);
		if (options.verify !== false) {
			const profile = JSON.parse(readFileSync(join(stage, ".pi/settings.json"), "utf8")) as { extensions: string[] };
			const compiled = profile.extensions.map(entry => resolve(stage, ".pi", entry).replace("/extensions/src/", "/extensions/dist/").replace(/\.ts$/, ".js"));
			const checks = [
				spawnSync(process.execPath, [join(stage, "pi/pi/packages/coding-agent/dist/bundle/cli.js"), "--help"], { cwd: stage, encoding: "utf8", timeout: 30_000, env: { PATH: process.env.PATH, HOME: "/nonexistent" } }),
				spawnSync(process.execPath, ["--input-type=module", "-e", "for (const path of process.argv.slice(1)) await import(path)", ...compiled], { cwd: stage, encoding: "utf8", timeout: 30_000, env: { PATH: process.env.PATH, HOME: "/nonexistent" } }),
				spawnSync(join(stage, "services/.venv/bin/python"), ["-c", "import pluto_services.kb.cli, pluto_services.msf_bridge.cli"], { cwd: stage, encoding: "utf8", timeout: 30_000, env: { PATH: process.env.PATH, PYTHONPATH: join(stage, "services"), PYTHONDONTWRITEBYTECODE: "1" } }),
			];
			for (const check of checks) if (check.status !== 0 || check.error) throw new Error(`offline runtime dependency check failed: ${check.error?.message ?? check.stderr.slice(0, 500)}`);
		}
		// Publication is protected by an exclusive sibling lock against peer deployers.
		const lock = `${destination}.deploy-lock`;
		mkdirSync(lock, { mode: 0o700 });
		try { if (existsSync(destination)) throw new Error("deployment destination appeared during staging"); renameSync(stage, destination); }
		finally { rmSync(lock, { recursive: true }); }
		return validateRuntime(destination);
	} catch (error) { rmSync(stage, { recursive: true, force: true }); throw error; }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const [source, destination] = process.argv.slice(2);
		if (!source || !destination) throw new Error("usage: deploy.js SOURCE ABSENT-DESTINATION");
		deployRuntime(source, destination);
		process.stdout.write(`Sanitized runtime deployed at ${resolve(destination)}\n`);
	} catch (error) { process.stderr.write(`deployment refused: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
