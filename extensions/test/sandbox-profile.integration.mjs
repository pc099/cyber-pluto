// Invoked by a root-owned local QA orchestrator through the deployed wrapper.
// Actual source profile + Pi SDK; only a scripted in-memory provider, no fetch.
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const runtime = process.env.PLUTO_CWD;
const engagement = process.env.PLUTO_QA_ENGAGEMENT;
assert.ok(runtime && engagement);
assert.equal(process.getuid(), Number(process.env.PLUTO_READINESS_UID));
globalThis.fetch = async () => { throw new Error('QA refuses every network fetch'); };
const load = path => import(pathToFileURL(join(runtime, path)).href);
const { createAgentSession, DefaultResourceLoader, SessionManager, SettingsManager } = await load('pi/pi/packages/coding-agent/dist/index.js');
const { AuthStorage } = await load('pi/pi/packages/coding-agent/dist/core/auth-storage.js');
const { ModelRuntime } = await load('pi/pi/packages/coding-agent/dist/core/model-runtime.js');
const { registerFauxProvider, fauxAssistantMessage, fauxToolCall } = await load('pi/pi/packages/ai/dist/compat.js');
const { getActiveBinding, bindingPath } = await load('extensions/dist/state/session-binding.js');
const { preflightSandboxSession, assertWorkspaceControls } = await load('extensions/dist/launcher/sandbox-preflight.js');
const { readOutcome, outcomePath } = await load('extensions/dist/lifecycle/provider-outcome.js');
const { buildSubAgentEnv } = await load('extensions/dist/delegation/spawn.js');
const { requestOperatorStop } = await load('extensions/dist/state/signer-health.js');
const { createFindingsRepo } = await load('extensions/dist/state/findings-repo.js');
const { resolveVerifier } = await load('extensions/dist/state/promotion-verifier.js');
const { DatabaseSync } = await import('node:sqlite');
let loadedExtensions = 0;
async function host(manager = SessionManager.create(runtime, join(engagement, 'sessions'))) {
 const faux = registerFauxProvider();
 const credentials = AuthStorage.inMemory();
 await credentials.modify(faux.getModel().provider, async () => ({type:'api_key',key:'synthetic-fixture-key'}));
 const modelRuntime = await ModelRuntime.create({credentials,modelsPath:null,refreshOnCreate:false});
 const model = faux.getModel();
 modelRuntime.registerProvider(model.provider,{baseUrl:model.baseUrl,api:model.api,models:[{...model}]});
 const settings = SettingsManager.create(runtime, process.env.PI_CODING_AGENT_DIR);
 settings.applyOverrides({retry:{enabled:true,maxRetries:2,baseDelayMs:1},compaction:{enabled:false}});
 const loader = new DefaultResourceLoader({cwd:runtime,agentDir:process.env.PI_CODING_AGENT_DIR,settingsManager:settings,noContextFiles:true,noPromptTemplates:true,noThemes:true});
 await loader.reload({resolveProjectTrust:async()=>true});
 assert.deepEqual(settings.drainErrors(),[]);
 const {session,extensionsResult} = await createAgentSession({cwd:runtime,agentDir:process.env.PI_CODING_AGENT_DIR,modelRuntime,model,settingsManager:settings,sessionManager:manager,resourceLoader:loader});
 assert.deepEqual(extensionsResult.errors,[]);
 loadedExtensions = extensionsResult.extensions.length;
 assert.equal(loadedExtensions,13);
 const configured = JSON.parse(readFileSync(join(runtime,'.pi/settings.json'),'utf8')).extensions.map(path=>resolve(runtime,'.pi',path));
 assert.deepEqual(extensionsResult.extensions.map(extension=>extension.path).sort(),configured.sort());
 assert.ok(loader.getSkills().skills.length>0);
 await session.bindExtensions({});
 return {session,faux,dispose(){session.dispose();faux.unregister();}};
}
async function tool(fixture,name,args) {
 fixture.faux.setResponses([fauxAssistantMessage(fauxToolCall(name,args),{stopReason:'toolUse'}),fauxAssistantMessage('fixture settled')]);
 await fixture.session.prompt('Execute this local QA fixture only.');
}
let first = await host();
let sessionFile;
try {
 await tool(first,'write',{path:join(engagement,'sdk-written.txt'),content:'actual SDK write'});
 assert.equal(readFileSync(join(engagement,'sdk-written.txt'),'utf8'),'actual SDK write');
 await tool(first,'write',{path:join(runtime,'sdk-denied.txt'),content:'must fail readonly'});
 assert.equal(existsSync(join(runtime,'sdk-denied.txt')),false);
 const marker = join(engagement,'out-of-scope-executed');
 await tool(first,'bash',{command:`curl --max-time 1 http://192.0.2.17; touch ${marker}`});
 assert.equal(existsSync(marker),false);
 const blocks = readFileSync(join(process.env.PLUTO_LOG_DIR,'red-lines.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
 assert.ok(blocks.some(row=>row.kind==='red_line' && row.toolName==='bash'));
 assert.ok(readFileSync(join(process.env.PLUTO_LOG_DIR,'tool-invocations.jsonl'),'utf8').includes('tool_call'));
 const syntheticToken = 'qa-bare-provider-access-with-no-pattern-shape';
 process.env.PLUTO_CODEX_ACCESS_TOKEN = syntheticToken;
 try {
  await tool(first,'bash',{command:'printf %s "$PLUTO_CODEX_ACCESS_TOKEN"'});
  assert.equal(readFileSync(join(process.env.PLUTO_LOG_DIR,'tool-invocations.jsonl'),'utf8').includes(syntheticToken),false);
  for (const file of readdirSync(join(process.env.PLUTO_EVIDENCE_DIR,'attempts'))) assert.equal(readFileSync(join(process.env.PLUTO_EVIDENCE_DIR,'attempts',file),'utf8').includes(syntheticToken),false);
 } finally {delete process.env.PLUTO_CODEX_ACCESS_TOKEN;}
 const binding = getActiveBinding(runtime);
 sessionFile = binding.sessionFile;
 assert.equal(binding.association.sandboxMode,'requested');
 const db = new DatabaseSync(join(process.env.PLUTO_STATE_DIR,'pluto.db'));
 try {
  const findings = createFindingsRepo(db,{verifier:resolveVerifier()});
  assert.equal(findings.isValidatedTrustworthy(1),true);
 } finally {db.close();}
 first.faux.setResponses([fauxAssistantMessage('',{stopReason:'error',errorMessage:'Codex error: This content was flagged for possible cybersecurity risk.'})]);
 await first.session.prompt('Initialize synthetic provider hold');
 assert.equal(readOutcome(binding).providerBlocked,true);
 const saved = readFileSync(outcomePath(binding),'utf8');
 preflightSandboxSession(sessionFile,runtime,process.env,join(engagement,'sessions'),{allowHeldDiagnostics:true});
 assert.equal(readFileSync(outcomePath(binding),'utf8'),saved);
 assert.throws(()=>preflightSandboxSession(sessionFile,runtime,process.env,join(engagement,'sessions')),/resume held/);
 assert.throws(()=>buildSubAgentEnv(runtime),/stopped|held|provider_blocked/);
 writeFileSync(join(process.env.PLUTO_STATE_DIR,'PAUSED'),'synthetic environmental pause');
 const selected = preflightSandboxSession(sessionFile,runtime,process.env,join(engagement,'sessions'),{allowHeldDiagnostics:true});
 assertWorkspaceControls(engagement,{selectedBinding:selected,headless:false,sandboxCheck:false});
 assert.throws(()=>assertWorkspaceControls(engagement,{selectedBinding:selected,headless:true,sandboxCheck:false}),/PAUSED/);
} finally {first.dispose();}
const resumed = await host(SessionManager.open(sessionFile));
try {
 const binding = getActiveBinding(runtime);
 assert.equal(binding.sessionFile,sessionFile);
 assert.equal(JSON.parse(readFileSync(bindingPath(sessionFile),'utf8')).association.stateDir,process.env.PLUTO_STATE_DIR);
 const resumedDb = new DatabaseSync(join(process.env.PLUTO_STATE_DIR,'pluto.db'));
 try {assert.equal(createFindingsRepo(resumedDb,{verifier:resolveVerifier()}).isValidatedTrustworthy(1),true);}
 finally {resumedDb.close();}
 resumed.faux.setResponses([fauxAssistantMessage('must stay held')]);
 await resumed.session.prompt('Continue without operator decision');
 assert.equal(resumed.faux.state.callCount,0);
 await resumed.session.prompt('/unpause');
 assert.equal(existsSync(join(process.env.PLUTO_STATE_DIR,'PAUSED')),false);
 await resumed.session.prompt('Provider hold remains after unpause');
 assert.equal(resumed.faux.state.callCount,0);
 await resumed.session.prompt('/provider-retry operator reviewed synthetic fixture');
 resumed.faux.setResponses([fauxAssistantMessage('one explicit synthetic retry')]);
 await resumed.session.prompt('One deliberate local retry');
 assert.equal(resumed.faux.state.callCount,1);
 assert.equal(readOutcome(binding).providerBlocked,false);
 assert.equal(readOutcome(binding).executionState,'unknown');
 const delegateEnv = buildSubAgentEnv(runtime);
 assert.equal(delegateEnv.PLUTO_KILL_FILE,process.env.PLUTO_KILL_FILE);
 assert.equal(delegateEnv.PLUTO_STATE_DIR,process.env.PLUTO_STATE_DIR);
 assert.throws(()=>writeFileSync(process.env.PLUTO_KILL_FILE,'agent cannot write'),/EACCES|EROFS|EPERM/);
 await requestOperatorStop(process.env.PLUTO_PROMOTION_SIGNER_SOCK);
 assert.ok(existsSync(process.env.PLUTO_KILL_FILE));
 assert.throws(()=>buildSubAgentEnv(runtime),/kill|stop|control/i);
 resumed.faux.setResponses([fauxAssistantMessage('must not run after STOP')]);
 await resumed.session.prompt('Continue after external stop');
 assert.equal(resumed.faux.state.callCount,1);
 // Exercise actual built-in dispatch guard even if caller bypasses input hook.
 resumed.faux.setResponses([fauxAssistantMessage(fauxToolCall('write',{path:join(engagement,'after-stop.txt'),content:'must not execute'}),{stopReason:'toolUse'}),fauxAssistantMessage('blocked')]);
 await resumed.session.agent.prompt('Exercise external-stop tool guard');
 assert.equal(existsSync(join(engagement,'after-stop.txt')),false);
 console.log(JSON.stringify({sandboxFullSourceProfile:'passed',extensions:loadedExtensions,provider:'in-memory only',workspaceWrite:true,readonlyRuntimeDenied:true,redLinePreexecutionBlock:true,durableAudit:true,signedTrustOnResume:true,holdPreserved:true,pauseRecovery:true,explicitRetry:true,externalStop:true,delegateGuards:true,targetTraffic:'none'}));
} finally {resumed.dispose();}
