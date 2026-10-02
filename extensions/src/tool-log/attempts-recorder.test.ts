import assert from "node:assert/strict";
import { test } from "node:test";
import { resetEngagement } from "../state/engagement.js";
import { redactSecrets } from "../shared/redact.js";
import { knownSecrets } from "./attempts-recorder.js";

test("bare injected access-token output is redacted even before engagement bootstrap", () => {
	const previous = process.env.PLUTO_CODEX_ACCESS_TOKEN;
	try {
		resetEngagement();
		const token = "qa-access-token-with-no-pattern-shape";
		process.env.PLUTO_CODEX_ACCESS_TOKEN = token;
		const safe = redactSecrets(JSON.stringify({ content: [{ type: "text", text: token }] }), knownSecrets());
		assert.equal(safe.includes(token), false);
		assert.ok(safe.includes("REDACTED"));
	} finally {
		if (previous === undefined) delete process.env.PLUTO_CODEX_ACCESS_TOKEN;
		else process.env.PLUTO_CODEX_ACCESS_TOKEN = previous;
	}
});
