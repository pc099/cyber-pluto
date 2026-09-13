/**
 * The human kill switch (Architecture §3.4 / §10 — "the ability to halt the
 * harness at any moment", the floor of the human's role).
 *
 * Realized as a file sentinel: if the kill file exists, every subsequent tool
 * call is blocked before it executes and the harness is asked to shut down.
 * A file (not a signal) because it is dead simple for the operator to trigger
 * from anywhere — `touch state/KILL_SWITCH` (or `!touch ...` inside Pi) — it
 * is observable/testable, and it works across Pi's isolated extension realms
 * and across any future delegated sub-agent process that shares the workspace.
 *
 * Granularity: the check runs per tool call, so "halt at any moment" means
 * "before the next consequential action". For a tool-driven agent the tool
 * call is the unit of consequence, so blocking before the next one is the
 * meaningful stop.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";

const DEFAULT_KILL_FILE = "state/KILL_SWITCH";

export function killSwitchPath(cwd: string): string {
	const override = process.env["PLUTO_KILL_FILE"];
	if (override && override.length > 0) {
		return override;
	}
	return join(cwd, DEFAULT_KILL_FILE);
}

export function isKillSwitchEngaged(cwd: string): boolean {
	return existsSync(killSwitchPath(cwd));
}
