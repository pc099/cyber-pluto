/**
 * kb-bridge: the thin TS→Python edge for the seeded knowledge base.
 *
 * This is IPC, not KB logic — all knowledge-base logic (vector store,
 * embeddings, ingestion, retrieval) lives in Python (`services/pluto_services/
 * kb`), per the CLAUDE.md boundary (no KB logic in the TS extensions). This
 * module only shells out to the Python query CLI and parses its JSON.
 *
 * The KB is an ENHANCEMENT to exploration, never a gate: any failure here
 * (KB not ingested, Python/venv missing, bad output) logs and returns no hits
 * rather than throwing into the agent loop. Exploration continues without it.
 */
import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const QUERY_TIMEOUT_MS = 20000;

export interface KbHit {
	id: string;
	source: string;
	score: number;
	cve: string | null;
	vendor: string | null;
	product: string | null;
	title: string | null;
	summary: string | null;
}

export interface KbQueryInput {
	product?: string | null;
	version?: string | null;
	service?: string | null;
}

export interface KbQueryOptions {
	limit?: number;
	minScore?: number;
}

export async function queryKb(cwd: string, fp: KbQueryInput, opts: KbQueryOptions = {}): Promise<KbHit[]> {
	if (!fp.product && !fp.version && !fp.service) {
		return [];
	}
	const python = join(cwd, "services", ".venv", "bin", "python");
	const args = [
		"-m",
		"pluto_services.kb.cli",
		"--kb-path",
		join(cwd, "state", "kb"),
		"query",
		"--limit",
		String(opts.limit ?? 3),
		"--min-score",
		String(opts.minScore ?? 0.25),
		"--json",
	];
	if (fp.product) args.push("--product", fp.product);
	if (fp.version) args.push("--version", fp.version);
	if (fp.service) args.push("--service", fp.service);

	try {
		const { stdout } = await execFileAsync(python, args, {
			cwd,
			env: { ...process.env, PYTHONPATH: join(cwd, "services") },
			timeout: QUERY_TIMEOUT_MS,
			maxBuffer: 4 * 1024 * 1024,
		});
		const parsed: unknown = JSON.parse(stdout.trim() || "[]");
		return Array.isArray(parsed) ? (parsed as KbHit[]) : [];
	} catch (err) {
		console.error("[pluto/kb-bridge] KB query failed (continuing without KB):", err instanceof Error ? err.message : err);
		return [];
	}
}
