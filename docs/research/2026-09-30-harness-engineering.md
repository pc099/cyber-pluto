# Cyber Pluto harness engineering research

Research date: 2026-09-30. Researcher: `pluto-harness-researcher`.
Status: research snapshot and original proposal. The board ratified a revised
design; implementation and final QA completed on 2026-10-01 in
[Decision 0008](../decisions/0008-research-led-reliability.md).
No implementation, target probing, paid model calls, access application or
historical attack replay was performed for this memo.

## Recommendation

Keep Pluto's Pi runtime and deterministic validation architecture. First make
its results, engagement identity and provider interruptions reliable. A new
orchestrator, more agents or a different model would not repair the recorded
attribution and trust defects. Implement three bounded slices after board
approval: strict verified-current results, explicit durable session binding,
and persisted provider-error/run outcomes. Defer workspace migration and full
execution supervision to separately tested work.

The evidence for these priorities is Decision 0007 and the inspected code;
external sources supply approaches and limitations, not proof that those
approaches already work in Pluto.

## Evidence from primary sources

Sources below were opened on the research date. A documented design is not an
independently replicated result. No numerical vendor performance comparison is
used to select Pluto's architecture.

| Source | What is established | Implication for Pluto |
| --- | --- | --- |
| [PentestGPT, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) | The original research identifies loss of whole-task context despite useful tool interpretation, and evaluates a three-module framework intended to reduce that loss. Research results apply to that paper's tasks and model configuration. | Preserve a coherent investigation state across restarts; a remembered chat is insufficient. The paper does not prove adding three new Pluto agents will improve reliability. |
| [CAI official repository](https://github.com/aliasrobotics/cai) | The repository is archived/read-only, with an August 28, 2026 archive notice. Its maintainers say no further releases, fixes or support will be provided. Preserved architecture covers agents, tools, handoffs, tracing and human review. | Useful historical architecture reference; unsuitable as an assumed actively maintained dependency. Its successor/product and performance statements are vendor claims. |
| [XBOW result interpretation](https://docs.xbow.com/console/guidance/interpreting-results/) | Product documentation distinguishes validated and informational findings and describes reproduction evidence and full test traces. It acknowledges coverage gaps. | Separate hypotheses, recorded reproductions, verified attestations and coverage. The vendor's zero-false-positive claim is not independently established here. |
| [XBOW validation benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | The owner now labels the 104-task set outdated, saturated by mid-2026 and historical. The repository defines injected flags, explicit objectives and service-health readiness. | Can inspire local smoke-test structure; passing this public set cannot establish frontier capability or broad real-world coverage. The owner's saturation statement is not independently measured here. |
| [Cybench project](https://cybench.github.io/) | Forty CTF tasks with evaluators and optional intermediary subtasks. Its leaderboard explicitly distinguishes guided/unguided outcomes and different task subsets, and flags one answer-leakage issue. | Record assistance, environment, task subset and evaluator access. Do not equate final-session success, guided progress or a leaked answer with an autonomous solve. |
| [CyberGym paper, revision March 24, 2026](https://arxiv.org/abs/2506.02548) | A research benchmark of 1,507 real vulnerabilities across 188 projects, centered on reproducible proof-of-concept inputs given descriptions and code. Reported paper results are historical model/scaffold evaluations. | Consider reproduction and patch-regression evaluation after Pluto's own reliability is sound. Its source-code task domain differs from a VulnHub network engagement. |
| [Anthropic long-running harness engineering, November 26, 2025](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) | Vendor engineering experiments use initialization, incremental work, persistent progress artifacts and realistic verification. The article reports premature completion and context-continuity failures; it does not establish multi-agent superiority. | Restore verified state before useful work and require evidence before completion. These coding-agent observations are an engineering analogy, not a pentesting benchmark result. |
| [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence) and [checkpointers](https://docs.langchain.com/oss/python/langgraph/checkpointers) | Official framework documentation binds checkpoints to thread IDs and describes checkpoint boundaries and pending writes so completed graph nodes are not rerun when a peer fails. | Use stable identities and persist completed-action outcomes. Checkpointed graph state does not by itself establish exactly-once arbitrary shell effects. No LangGraph migration is proposed. |
| [Bubblewrap maintainers](https://github.com/containers/bubblewrap) | Bubblewrap supplies sandbox mechanisms; the caller's arguments determine its security policy. Read-only mounts are a filesystem control, not an automatic complete boundary. | Test the actual mounts, user, network policy, signing socket and dependencies. Relocating one directory cannot alone prove confinement. |

### Legitimate model access and provider interruptions

OpenAI documents Daybreak Blue for authorized defensive workflows and separately
approved Red access for advanced controlled validation and penetration testing.
Approval depends on identity/service, workspace or API organization/project,
model and product surface. Applying is not approval. Access does not configure
the harness's scope or isolation. False positives should be reported with the
available client/request details. These statements do not establish Pluto's
account eligibility. [Official access documentation](https://learn.chatgpt.com/docs/cyber-safety)

The API documentation distinguishes API safeguards from Codex safeguards,
documents `cyber_policy` restrictions, and says request-level errors may arrive
midstream for Zero Data Retention organizations. Application controls remain
separate. [Official API cybersecurity checks](https://developers.openai.com/api/docs/guides/safety-checks/cybersecurity)

Local inspection: `pi/pi/packages/ai/src/providers/openai-codex.ts` declares
OAuth and `https://chatgpt.com/backend-api`; the reviewed trace used
`openai-codex`. Therefore API-project approval cannot be assumed to cover the
observed connection. The 27 historical errors were formatted provider notices,
not demonstrated API `cyber_policy` objects. Preserve this distinction when
implementing classification. Do not rotate identities, conceal operations or
route around a policy block; interruption recovery is independent of eligibility.

## Direction of the field: bounded inference

These sources support a direction toward execution-based evidence, explicit
evaluation environments, durable state, traceability and a workflow spanning
discovery, reproduction and remediation. This is a synthesis of the cited
designs, not a prediction of every product or an independently measured industry
trend. Public CTF suites remain useful for controlled checks, but saturation,
training exposure and task-specific scoring limit capability claims. More
agent autonomy increases the need to separate the decision-maker from scope,
attestation and outcome evaluation.

For Pluto, the useful next capability is trustworthy continuity. Measure
verified current outcomes, assistance, readiness failures, interruption recovery,
cleanup debt and budget separately. A higher root-success percentage that
silently changes engagements or counts unsigned rows would be a regression.

## Recorded defects and local integration points

Decision 0007 contains the detailed trace and empirical fixture results. The
following pre-implementation code paths were inspected read-only for this
research; the recorded line numbers and defects describe that snapshot:

* `extensions/src/state/engagement.ts:50`: per-module singleton; state opens
  before checking identity; label defaults to `ad-hoc`, host to `localhost`.
  Extensions load in separate module realms, so a single lifecycle variable
  cannot protect every extension's bootstrap.
* `extensions/src/state/findings-repo.ts:164`: the existing trust helper returns
  true for non-validated status and without a verifier. At line 321 the milestone
  predicate counts promotion rows without current status or signature checks.
  Neither is a strict current-trusted fact predicate.
* `extensions/src/lifecycle/index.ts:202`: session startup clears a pause and
  warns about absent/loopback target rather than refusing rebinding. Summaries
  are published pre-call; provider-only errors do not need a tool call.
* `extensions/src/lifecycle/run-summary.ts:63`: root/foothold boolean inputs
  drive the milestone even when trusted validation count is zero.
* `sandbox/run-sandboxed.sh:53`: whole-host read-only bind, same absolute
  engagement path, writable host `/tmp`, repository chdir under `/root`, and a
  fallback when bubblewrap is unavailable. These are issues to characterize,
  not claims that an escape happened in the reviewed trace.

Pi provides extension hooks for identity and outcome persistence. Subsequent
board review identified a generic cancellation race requiring the small core
patch documented in Decision 0008; the original integration points follow:

* `core/extensions/types.ts:564` has `session_start` reasons
  `startup/reload/new/resume/fork`; there is no separate `session_switch` hook.
* `ctx.sessionManager.getSessionId()`, `getSessionFile()`, `getEntries()` and
  `getBranch()` expose identity/history. `pi.appendEntry()` records custom data.
  Fork metadata must respect the chosen branch rather than an unrelated leaf.
* `core/agent-session.ts:662` dispatches `message_end` to extensions before
  appending the assistant message. Capture the event's assistant error fields;
  scanning already persisted entries there can miss the current error.
* `agent_end` can precede automatic retry/continuation. `agent_settled`, defined
  in `core/extensions/types.ts:740`, means retries/compaction/queued continuation
  have settled; use it for turn terminal telemetry where supported.
* `core/session-manager.ts:1029` defers initial persistence until an assistant
  exists. A custom binding entry alone cannot promise crash-durable binding
  before the first model response. Persist an atomic descriptor as well.

## Concrete proposal for board approval

### Slice A — Strict verified-current facts

Add one explicit predicate for authoritative outcomes. Require eligible current
status (`validated` or `submitted`), a verifier, valid promotion signature and
matching finding/target/validation/validator relationships. Consume it in
milestones, progress detection, reports and validator trust responses. Ensure a
submission does not make a verified finding disappear from historical progress.
Keep recorded deterministic reproduction visible with its trust qualification.

Make Gate 2 refuse absent verification as well as an invalid signature, if the
board approves the deliberate tightening of historical no-verifier behavior.
Update development tests to use ephemeral signed fixtures for trusted positives;
unsigned runs may still support explicitly labeled diagnostics. Do not claim
this closes the already recorded forged-validation-row residual: attestation
issuance itself still needs independent validation-boundary work.

Acceptance: signed eligible finding counts; unsigned, missing verifier, invalid
signature, rejected/candidate status and mismatched associations do not yield
trusted root/foothold. Formerly signed then submitted remains eligible; formerly
signed then rejected does not. Gate verdict/report/summary agree. Gate 2 preserves
its human approval requirement and rejects unsigned/no-verifier fixtures.

### Slice B — Explicit session/engagement binding and bounded readiness

Write a versioned durable binding keyed by Pi session identity, with target
label/host, canonical ledger/evidence/log roots, scope reference or snapshot,
signing mode and sandbox mode. Store a corresponding custom session entry for
trace/fork continuity. Atomic write and session-ID matching protect against
accidental partial state; agent-writable metadata is not a new security boundary.

Before any DB bootstrap, validate explicit launcher environment and the binding.
On resume require an exact match; diagnose absent/mismatched values and refuse
target mutations. This first slice need not auto-load environment from saved
metadata. Bare `pi --session` must not create an `ad-hoc` fallback ledger. An
old unbound transcript needs an explicit operator launcher adoption operation;
do not guess its target from narrative or silently copy its evidence. Adoption
must not promote old unsigned findings or imply sandbox readiness.

Put the identity check in the common engagement bootstrap used by every
extension, not just lifecycle. Refresh or invalidate cached engagement objects
on session new/resume/fork transitions in every module realm. Fork inheritance
needs explicit semantics: preserve engagement association, assign new run/session
identity, and do not inherit a falsely cleared interruption. Keep diagnostics
available without target mutation.

Bounded readiness here means identifiable roots, matching saved metadata and
accurate configured modes. It does not prove scope authority, reachability,
signer service availability or isolation. Reject missing required configuration;
do not fabricate a readiness green status for checks that did not run.

Acceptance: named scratch session resumes against the same scratch ledger;
missing environment, changed ledger/host, conflicting binding, corrupt descriptor
and unsupported legacy resume fail before target creation. Explicit new sessions
bind once; session switching cannot reuse the prior cached target. A fork cannot
select another branch's binding. At least two extensions in separate realms
observe the same binding checks. Diagnostics neither modify historical ledgers
nor rewrite signing/sandbox mode to make a mismatch pass.

### Slice C — Provider error persistence and honest terminal telemetry

Observe assistant errors at `message_end`, with `agent_end` as a compatible
fallback and `agent_settled` for final turn telemetry. Store a versioned outcome
record per bound session/run. Classify structured codes when actually available;
use narrow, tested matching for the historical formatted refusal. Do not label
every error as cyber policy or classify ordinary assistant prose as an error.

Persist `provider_blocked` distinctly from authentication, rate-limit/network,
scope denial and hard caps. Keep timestamps, provider/model, available request
identifier, last completed tool reference and a bounded sanitized error summary.
Avoid secrets/full prompts. Preserve an existing deterministic hard-cap stop;
a later bookkeeping event must not replace it with `in_progress` or `finished`.
A settled conversational turn does not automatically mean engagement completion.

No automatic retry/fallback on classified policy rejection. Operator continuation
does not erase the last interruption: record a new attempt and update the state
only after actual recovery evidence. Preserve unresolved execution/cleanup as
unknown or owed; this slice does not implement exactly-once shell effects or
invent a successful cleanup. Retain a hard elapsed deadline until a separately
approved clock/supervisor design changes it; label it process/run elapsed, not
active target-testing time.

Acceptance: a synthetic error with no tool call produces a persisted interruption
and final qualified summary; a midstream error event after a completed dummy tool
retains that tool's outcome. Success later records recovery without deleting
history. Restart preserves the block. Generic network error is distinct; quoted
policy text in normal assistant output is not classified. Hard-cap state is not
overwritten on settlement. Tests make no provider calls or target requests.

## Deferred work and proof boundaries

1. **Sandbox workspace/startup:** map actual source traversal, destination mounts,
   repository dependencies, writable roots and signing socket. Test UID-drop
   and network controls with benign local fixtures; migrate copies before any
   saved-state replacement. Relocation alone is not approved as a proven fix.
2. **Side-effect supervision and cleanup debt:** durable action intent/completion,
   owned process/resource identifiers, uncertain-outcome reconciliation and
   timeout/teardown independent of a model response. Do not replay arbitrary
   interrupted shell commands or terminate unrelated processes.
3. **Scope amendments and attestation authority:** typed operator transactions
   and a stronger independent validation/signing boundary. A metadata hash in
   an agent-writable file does not establish operator authority.
4. **Execution-channel contract:** nonce/argument propagation and UID/EUID
   semantics with controlled fixtures before any lab evaluation.
5. **Benchmarking:** isolated current tasks with evaluator separation, held-out
   outcomes and assistance/cost/time/cleanup reporting. Do not launch vulnerable
   images or buy model runs merely because public suites were researched.

The board should approve or rewrite each slice explicitly. Implementation QA
should run relevant existing tests plus the acceptance scenarios above, reporting
local-fixture proof separately from live sandbox and authorized-engagement proof.
This memo's source review establishes neither repaired sandbox operation nor a
new successful target solve.
