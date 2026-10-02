/** Local payload fixture for the real production launcher transaction.
 * No Pi/model/provider invocation: the payload is a fixed ledger probe or an
 * absent file. An explicitly synthetic key only satisfies provider preflight. */
import assert from "node:assert/strict";
import { buildPlan } from "../dist/launcher/index.js";
import { runSandbox } from "../dist/launcher/sandbox.js";

const [label, mode] = process.argv.slice(2);
assert.match(label ?? "", /^qa-retention-[a-f0-9]+$/);
assert.ok(["normal", "missing"].includes(mode));
process.env.GROQ_API_KEY = "synthetic-local-qa-no-provider-request";
const parsed = buildPlan(["127.0.0.1", "--label", label, "--sandbox", "--provider", "groq", "--headless"]);
assert.ok(parsed.plan, JSON.stringify(parsed));
const plan = parsed.plan;
plan.cliArgs = [mode === "normal" ? "extensions/dist/launcher/ledger-probe.js" : "extensions/dist/launcher/qa-absent-payload.js", "--session-dir", "unused"];
const result = await runSandbox(plan, undefined, []);
assert.equal(result, 1, "production cleanup must report retained protection");
console.log(JSON.stringify({ qaProductionRetention: mode, result, modelOrTarget: "none" }));
