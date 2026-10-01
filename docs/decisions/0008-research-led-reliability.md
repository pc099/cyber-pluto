# Decision 0008 — Research-led harness reliability

Date: 2026-09-30. Research: `docs/research/2026-09-30-harness-engineering.md`.
The operator requested a reusable web research agent, research on the recorded
issues and the field's direction, four-role review, and implementation of fixes
the board approves. No new target engagement or paid provider evaluation is part
of this engineering task.

## Research and review

The reusable adviser is `.codex/agents/pluto-harness-researcher.toml`, with skill
`.agents/skills/pluto-harness-research/SKILL.md`. It inherits available web tools
and permissions. It is not a fifth board voter and cannot grant unrestricted
network/account access. The dated memo contains primary-source links, local
integration evidence, benchmark limitations and three bounded proposals.

Architect, security and griller reviewed independently; the coordinating agent
performed QA as the fourth voice. Reviewers received the other positions and
completed a huddle. The architect's first broader review was provider-rejected;
its subsequent review intentionally narrowed coverage to persistence, lifecycle
and report semantics. The security and griller reviews cover the full proposal.
That limitation is retained rather than treating a failed turn as approval.

Fresh baseline: extensions compiled and all 151 tests passed outside the tool
sandbox. The sandboxed baseline stalled after its first test files; local
loopback/Unix-socket fixtures required the approved execution context. This is
baseline software evidence, not a repaired sandbox or new target solve.

## Ratified scope

### A — Verified current results

APPROVE across all four voices, with one strict predicate: current status is
`validated` or `submitted`, a verifier exists, promotion/finding/target/passed
validation associations agree, and the signature verifies. Share it across
milestones, progress, reports, Gate 1 trust wording and Gate 2. Submitted facts
retain eligible progress. Credential recovery remains visible separately and
does not imply a verified execution foothold.

Gate 2 deliberately tightens the historical no-verifier behavior. Recheck after
operator UI waits and atomically insert the approval record with the status
transition, rolling back on refusal. Unsigned reproductions remain qualified
diagnostic records; they are not trusted facts or submission-ready results.
The forged-validation-row residual remains open: this predicate does not make
attestation issuance independent of the writable validation ledger.

### B — Durable explicit session binding

Initial verdict REWRITE-REQUIRED; APPROVE after these concrete changes:

- Locate a versioned descriptor beside the canonical actual Pi session file,
  independently of the supplied engagement directory. Exclusive atomic creation
  rejects conflicts and allows identical readers/writers.
- Support launcher `--session PATH|ID` with ambiguity rejection and explicit
  `--adopt-session` for an unbound legacy transcript. Adoption cannot overwrite
  an existing association, repair trust, or infer targets from narrative.
- Place new sessions under the writable engagement workspace. Existing session
  paths are not silently migrated; inaccessible paths remain readiness failures.
- Install input/tool guards first in the main profile and delegated profiles.
  Startup exceptions alone are insufficient because Pi catches handler failures.
  Validate binding/configuration before common DB bootstrap writes any schema
  or target. Close stale cached handles before validating transitions.
- Determine resume from persisted history, not event reason alone. Respect
  selected-branch metadata for forks, give each session its own identity and
  retain interruption provenance. Ephemeral delegates require an explicit
  inherited parent association and cannot reset its interruption constraints.

Descriptor agreement is continuity/readiness metadata, not an operator authority
boundary or evidence of reachability, signer health, or sandbox confinement.

### C — Provider interruption and settlement

Persistence/telemetry APPROVE initially; griller required a concrete no-retry
rewrite. All four voices approve the revised generic cancellation integration:

- Persist actual assistant errors at `message_end`, with narrow policy matching
  and distinct authentication, rate, network and other categories. Preserve the
  original error and stop reason. Retain sanitized interruption history, available
  request details and the last completed tool reference.
- Call the supported context abort and keep persistent input/tool holds. An
  explicit operator recovery attempt is recorded separately; a successful chat
  reply cannot establish pending-action, cleanup or engagement completion.
- Fix Pi's generic cancellation race with a run cancellation latch. Reset it at
  accepted explicit-run entry before asynchronous hooks. Check it before and
  after awaited retry/compaction work and before automatic continuation. Clear
  cancelled-run queues, including items queued after cancellation. Keep policy
  classification in Pluto rather than adding it to Pi core.
- Publish `awaiting_operator` for a settled ordinary turn. Preserve hard-cap and
  interruption precedence. Use accurate process/run elapsed-time labels and
  align the launcher's default deadline with lifecycle's 5400 seconds.

This slice must prove actual Pi behavior with a fake provider: a policy error
also containing transient wording must cause one request, queued messages must
not leak, ordinary transient retry must still work, and later explicit recovery
must retain historical interruption evidence. A telemetry flag alone is not
acceptance.

## Deferred scope and verification

Sandbox workspace migration, full process supervision, cleanup authority and
inventory, typed scope amendments, independent privileged re-validation, UID/EUID
execution contracts, and live benchmark/target evaluation remain separately
tracked work. Research does not establish those features or authorize their
external execution.

## Implementation and final QA — 2026-10-01

A, B and C are implemented in parent commit `fb011fb`; the reusable agent and
skill were created in `4f93aa1`. Final architect and griller software reviews APPROVE
within the recorded scope. Security's final approval required empirical checks
for failed recovery retries and damaged outcome persistence; coordinating-agent
QA satisfied those conditions. QA APPROVE for the measured local software scope.
The architect's earlier narrowed coverage limitation remains in force.

Integration corrections retained the agreed design: the first guard now performs
common ledger bootstrap inside its guarded startup block, so Pi catching another
extension's exception cannot permit built-in execution. A nested delegate checks
its own interruption before spawning another child. Canonical absolute evidence
references now use `resolve(cwd, ref)` in five writers and the digest reader;
relative references still work. No attestation scheme was added: the current
promotion signs an evidence reference, and the digest helper test does not prove
byte-hash enforcement by current promotions. Evidence authenticity remains open.

Actual final checks:

- `extensions`: `npm run build` passed; `timeout 90 npm test` passed **184/184**,
  zero skipped, approximately 21 seconds. Local HTTP/Unix-socket/Chromium fixtures
  ran in the approved execution context outside the tool sandbox. The first
  integrated full run found two legacy red-lines fixtures missing explicit
  binding; those fixtures were corrected and their 22 tests and final suite pass.
- `extensions`: `npm run test:reliability` passed **8/8** using the rebuilt real
  Pi SDK, scripted in-memory provider, actual agent-core built-in dispatch and
  scratch files. No model API or live target was used. Checks cover missing
  configuration, corrupt ledger, completed-tool then policy interruption,
  suppression of late queues/retry, actual transcript restart and held input,
  explicit recovery retaining history, ordinary network retry, failed deliberate
  recovery consuming exactly one request, partial-tool suppression, corrupt
  outcome metadata and an unreadable journal retaining the hold.
- Pi: focused cancellation tests **9/9**, affected existing retry, compaction,
  queue and event suites **60/60**. `npm run check` from the monorepo and
  `npm run build` from the coding-agent package both exited zero. The check
  includes formatting, dependency/import/entry checks, lock consistency,
  TypeScript and browser smoke. The rebuilt SDK and CLI are in use locally.
- `git diff --check` passed. The tracked portable Pi patch applies exactly to
  a scratch reconstruction of its pinned base; a second application is
  idempotent. Both core and test bytes match the development checkout.

The Pi submodule's instructions prohibit committing without explicit operator
request. Its two source changes remain uncommitted, and the parent repository
preserves both in `patches/pi/abort-continuation.patch`, with a checked application
helper and build recipe. Fresh checkouts must apply and rebuild this patch before
running the integration suite or Pluto.

No sandbox startup retry, live target engagement, cleanup inventory, paid
provider evaluation, provider-access application or external submission occurred.
Outcome/session metadata is writable continuity data, not a privileged security
boundary. The run clock includes idle and interruption time; token/no-progress
counters remain process-local. Independent validation authority, forged passed
rows, process supervision and sandbox relocation remain the next scoped work.
