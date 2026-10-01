import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { createAgentSession, DefaultResourceLoader, SessionManager, SettingsManager } from "../../pi/pi/packages/coding-agent/dist/index.js";
import { AuthStorage } from "../../pi/pi/packages/coding-agent/dist/core/auth-storage.js";
import { ModelRuntime } from "../../pi/pi/packages/coding-agent/dist/core/model-runtime.js";
import { registerFauxProvider, fauxAssistantMessage, fauxToolCall } from "../../pi/pi/packages/ai/dist/compat.js";
import bindingExtension from "../dist/engagement-binding/index.js";
import lifecycleExtension from "../dist/lifecycle/index.js";
import toolLogExtension from "../dist/tool-log/index.js";
import { getActiveBinding } from "../dist/state/session-binding.js";
import { resetEngagement } from "../dist/state/engagement.js";
import { readOutcome, outcomePath, outcomeHistoryPath } from "../dist/lifecycle/provider-outcome.js";

// Real Pi SDK, real built-in write tool, scripted in-memory provider. No network
// model calls, live target, protected-file access or external credentials.
const savedEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.startsWith("PLUTO_")));
const scratch = [];
const POLICY = "Codex error: This content was flagged for possible cybersecurity risk. network error 503";
after(() => {
	resetEngagement();
	for (const key of Object.keys(process.env)) if (key.startsWith("PLUTO_")) delete process.env[key];
	Object.assign(process.env, savedEnv);
	for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

function configure(dir) {
	resetEngagement();
	for (const key of Object.keys(process.env)) if (key.startsWith("PLUTO_")) delete process.env[key];
	Object.assign(process.env, {
		PLUTO_TARGET_LABEL: "sdk-fixture", PLUTO_TARGET_HOST: "127.0.0.1", PLUTO_SCOPE_HOSTS: "127.0.0.1",
		PLUTO_STATE_DIR: join(dir, "state"), PLUTO_LOG_DIR: join(dir, "logs"), PLUTO_EVIDENCE_DIR: join(dir, "evidence"),
		PLUTO_SANDBOX_MODE: "disabled", PLUTO_LAUNCHER: "1", PLUTO_PROMOTION_PUBKEY: join(dir, "absent.pub"),
	});
}

async function host(dir, factories, manager = SessionManager.create(dir, join(dir, "sessions"))) {
	const faux = registerFauxProvider();
	const auth = AuthStorage.inMemory();
	await auth.modify(faux.getModel().provider, async () => ({ type: "api_key", key: "faux-fixture-key" }));
	const runtime = await ModelRuntime.create({ credentials: auth, modelsPath: join(dir, "models.json") });
	const model = faux.getModel();
	runtime.registerProvider(model.provider, { baseUrl: model.baseUrl, api: model.api, models: [{ id: model.id, name: model.name, api: model.api, reasoning: model.reasoning, input: model.input, cost: model.cost, contextWindow: model.contextWindow, maxTokens: model.maxTokens, baseUrl: model.baseUrl }] });
	const settings = SettingsManager.create(dir, dir);
	settings.applyOverrides({ retry: { enabled: true, maxRetries: 2, baseDelayMs: 1 }, compaction: { enabled: false } });
	const loader = new DefaultResourceLoader({ cwd: dir, agentDir: dir, settingsManager: settings, extensionFactories: factories, noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true });
	await loader.reload();
	const { session, extensionsResult } = await createAgentSession({ cwd: dir, agentDir: dir, modelRuntime: runtime, model, settingsManager: settings, sessionManager: manager, resourceLoader: loader, tools: ["write"] });
	assert.deepEqual(extensionsResult.errors, []);
	await session.bindExtensions({});
	return { session, faux, dispose: () => { session.dispose(); faux.unregister(); } };
}

test("failed startup blocks a real built-in tool and input before any fallback ledger exists", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-missing-")); scratch.push(dir);
	configure(dir);
	delete process.env.PLUTO_TARGET_HOST;
	const fixture = await host(dir, [bindingExtension, toolLogExtension]);
	try {
		fixture.faux.setResponses([fauxAssistantMessage("This response must not be requested")]);
		await fixture.session.prompt("continue");
		assert.equal(fixture.faux.state.callCount, 0);
		// Drive agent-core's actual tool dispatch below the input hook. Calling a
		// tool object's execute method directly omits Pi's tool interception hooks.
		fixture.faux.setResponses([
			fauxAssistantMessage(fauxToolCall("write", { path: "should-not-exist", content: "fixture" }), { stopReason: "toolUse" }),
			fauxAssistantMessage("The blocked tool returned a diagnostic"),
		]);
		await fixture.session.agent.prompt("exercise the built-in tool guard");
		const result = fixture.session.agent.state.messages.find(message => message.role === "toolResult");
		assert.ok(result);
		assert.match(JSON.stringify(result), /binding blocked|missing PLUTO_TARGET_HOST/i);
		assert.equal(existsSync(join(dir, "should-not-exist")), false);
		assert.equal(existsSync(join(dir, "state/pluto.db")), false);
	} finally { fixture.dispose(); }
});

test("valid metadata with a corrupt ledger blocks input and built-in dispatch", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-corrupt-")); scratch.push(dir); configure(dir);
	mkdirSync(join(dir, "state"), { recursive: true });
	writeFileSync(join(dir, "state/pluto.db"), "corrupt fixture ledger");
	const fixture = await host(dir, [bindingExtension, toolLogExtension]);
	try {
		fixture.faux.setResponses([fauxAssistantMessage("must not be requested")]);
		await fixture.session.prompt("continue");
		assert.equal(fixture.faux.state.callCount, 0);
		fixture.faux.setResponses([
			fauxAssistantMessage(fauxToolCall("write", { path: "should-not-exist", content: "fixture" }), { stopReason: "toolUse" }),
			fauxAssistantMessage("blocked"),
		]);
		await fixture.session.agent.prompt("exercise startup readiness guard");
		const result = fixture.session.agent.state.messages.find(message => message.role === "toolResult");
		assert.ok(result?.isError);
		assert.match(JSON.stringify(result), /database|file is not/i);
		assert.equal(existsSync(join(dir, "should-not-exist")), false);
		assert.equal(readFileSync(join(dir, "state/pluto.db"), "utf8"), "corrupt fixture ledger");
	} finally { fixture.dispose(); }
});

test("completed tool then policy plus transient wording suppresses retry and late queues; restart and deliberate recovery retain history", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-policy-")); scratch.push(dir); configure(dir);
	let live;
	const lateQueue = pi => pi.on("agent_end", event => {
		if (event.messages.some(message => message.role === "assistant" && message.stopReason === "error")) live.session.followUp("queued after cancellation");
	});
	live = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension, lateQueue]);
	let sessionFile;
	try {
		live.faux.setResponses([
			fauxAssistantMessage(fauxToolCall("write", { path: "completed.txt", content: "completed fixture" }, { id: "completed-tool" }), { stopReason: "toolUse" }),
			fauxAssistantMessage("", { stopReason: "error", errorMessage: POLICY }),
			fauxAssistantMessage("This retry must not run"),
		]);
		await live.session.prompt("run the local fixture");
		assert.equal(live.faux.state.callCount, 2);
		assert.equal(live.session.pendingMessageCount, 0);
		assert.equal(readFileSync(join(dir, "completed.txt"), "utf8"), "completed fixture");
		const binding = getActiveBinding(dir);
		const outcome = readOutcome(binding);
		assert.equal(outcome.providerBlocked, true);
		assert.equal(outcome.lastCompletedTool.toolCallId, "completed-tool");
		assert.equal(outcome.executionState, "unknown");
		const persistedError = live.session.sessionManager.getEntries().find(entry => entry.type === "message" && entry.message.role === "assistant" && entry.message.stopReason === "error");
		assert.equal(persistedError.message.errorMessage, POLICY);
		assert.equal(JSON.parse(readFileSync(join(dir, "state/run-summary.json"))).stopReason, "provider_blocked");
		sessionFile = live.session.sessionFile;
	} finally { live.dispose(); }
	resetEngagement();
	const restarted = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension], SessionManager.open(sessionFile));
	try {
		restarted.faux.setResponses([fauxAssistantMessage("responsive")]);
		await restarted.session.prompt("continue without a recovery decision");
		assert.equal(restarted.faux.state.callCount, 0);
		await restarted.session.prompt("/provider-retry approved access was reviewed for this fixture");
		await restarted.session.prompt("check responsiveness");
		assert.equal(restarted.faux.state.callCount, 1);
		const binding = getActiveBinding(dir);
		const outcome = readOutcome(binding);
		assert.equal(outcome.providerBlocked, false);
		assert.equal(outcome.state, "awaiting_operator");
		assert.equal(outcome.executionState, "unknown");
		assert.equal(outcome.cleanupState, "unknown");
		const history = readFileSync(outcomeHistoryPath(binding), "utf8");
		assert.match(history, /provider_error/);
		assert.match(history, /operator_retry_started/);
		assert.match(history, /provider_recovered/);
		assert.equal(readFileSync(join(dir, "completed.txt"), "utf8"), "completed fixture");
	} finally { restarted.dispose(); }
});

test("ordinary transient provider failures still retry and a quoted policy notice is ordinary prose", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-network-")); scratch.push(dir); configure(dir);
	const fixture = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension]);
	try {
		fixture.faux.setResponses([fauxAssistantMessage("", { stopReason: "error", errorMessage: "network error 503" }), fauxAssistantMessage(POLICY)]);
		await fixture.session.prompt("test a synthetic transient failure");
		assert.equal(fixture.faux.state.callCount, 2);
		assert.equal(readOutcome(getActiveBinding(dir)).providerBlocked, false);
		assert.equal(readOutcome(getActiveBinding(dir)).state, "awaiting_operator");
	} finally { fixture.dispose(); }
});

test("a deliberate policy recovery that fails with a network error consumes one request and retains the hold", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-retry-")); scratch.push(dir); configure(dir);
	const fixture = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension]);
	try {
		fixture.faux.setResponses([fauxAssistantMessage("", { stopReason: "error", errorMessage: POLICY })]);
		await fixture.session.prompt("initialize a synthetic policy hold");
		assert.equal(fixture.faux.state.callCount, 1);
		await fixture.session.prompt("/provider-retry operator reviewed fixture access");
		fixture.faux.setResponses([
			fauxAssistantMessage("", { stopReason: "error", errorMessage: "network error 503" }),
			fauxAssistantMessage("automatic retry must not run"),
		]);
		await fixture.session.prompt("one deliberate request");
		assert.equal(fixture.faux.state.callCount, 2);
		const outcome = readOutcome(getActiveBinding(dir));
		assert.equal(outcome.providerBlocked, true);
		assert.equal(outcome.lastError.category, "network");
		assert.equal(outcome.retryAllowance, undefined);
		await fixture.session.prompt("continue without another decision");
		assert.equal(fixture.faux.state.callCount, 2);
	} finally { fixture.dispose(); }
});

test("a failed streamed response cannot execute its partial tool call", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-partial-")); scratch.push(dir); configure(dir);
	const fixture = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension]);
	try {
		fixture.faux.setResponses([fauxAssistantMessage(fauxToolCall("write", { path: "partial.txt", content: "must not execute" }), { stopReason: "error", errorMessage: POLICY })]);
		await fixture.session.prompt("test a failed streamed response");
		assert.equal(fixture.faux.state.callCount, 1);
		assert.equal(existsSync(join(dir, "partial.txt")), false);
		assert.equal(readOutcome(getActiveBinding(dir)).lastCompletedTool, undefined);
	} finally { fixture.dispose(); }
});

test("corrupt interruption metadata holds provider input and built-in dispatch", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-outcome-")); scratch.push(dir); configure(dir);
	const fixture = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension]);
	try {
		writeFileSync(outcomePath(getActiveBinding(dir)), "{corrupt fixture");
		fixture.faux.setResponses([fauxAssistantMessage("must not run")]);
		await fixture.session.prompt("continue");
		assert.equal(fixture.faux.state.callCount, 0);
		fixture.faux.setResponses([
			fauxAssistantMessage(fauxToolCall("write", { path: "corrupt-outcome.txt", content: "must not run" }), { stopReason: "toolUse" }),
			fauxAssistantMessage("held"),
		]);
		await fixture.session.agent.prompt("exercise outcome guard");
		assert.equal(existsSync(join(dir, "corrupt-outcome.txt")), false);
	} finally { fixture.dispose(); }
});

test("unreadable interruption journal preserves cancellation and holds later requests", async () => {
	const dir = mkdtempSync(join(tmpdir(), "pluto-sdk-journal-")); scratch.push(dir); configure(dir);
	const breakJournal = pi => pi.on("before_agent_start", () => {
		const path = outcomeHistoryPath(getActiveBinding(dir));
		rmSync(path);
		mkdirSync(path);
	});
	const fixture = await host(dir, [bindingExtension, toolLogExtension, lifecycleExtension, breakJournal]);
	try {
		fixture.faux.setResponses([
			fauxAssistantMessage("", { stopReason: "error", errorMessage: POLICY }),
			fauxAssistantMessage("automatic retry must not run"),
		]);
		await fixture.session.prompt("exercise persistence failure");
		assert.equal(fixture.faux.state.callCount, 1);
		await fixture.session.prompt("continue");
		assert.equal(fixture.faux.state.callCount, 1);
		assert.equal(fixture.session.pendingMessageCount, 0);
	} finally { fixture.dispose(); }
});
