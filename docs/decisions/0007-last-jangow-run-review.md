# Decision 0007 — Last Jangow session: observed success, unreliable continuity

Date: 2026-09-30. Scope: after-action review of Pi session
`01a0d800-700c-74a0-ad83-4413dd373f75`. No harness implementation change is made
by this decision. No historical target commands were replayed.

## Board and verdict

The operator requested the four-role review board. Three delegated agents
independently reviewed architecture, cybersecurity/methodology and adversarial
criticism; the coordinating agent performed empirical QA as the fourth member,
within the environment's four-total-agent limit. The members then received
each other's positions and QA results and completed a huddle.

**Consensus: REWRITE-REQUIRED for trusted completion and reliable resume.**
Accept the narrower historical result: recorded, operator-assisted Jangow
testing produced root execution and a deterministic validation pass. Cleanup
output verifies absence of seven named target paths. A trusted signed promotion,
a coherent named-engagement foothold-to-root record, fully hands-off solving,
sandbox confinement and complete restoration are not established.

The operator corrected control state and granted an exact scope amendment;
the final technical sequence was selected and executed by the agent. Do not
misstate this as the operator supplying the final technical recipe, or as an
uninterrupted autonomous solve from initial reconnaissance.

The architect's first huddle turn received a provider cybersecurity error. It
subsequently completed a narrower software-correctness huddle limited to
metadata, trust predicates, lifecycle state and QA results. The other roles
completed their broader after-action huddles. That interruption does not change
the observed session evidence or permit claiming independent live verification.

## Sources and attribution

Primary trace:
`/root/.pi/agent/sessions/--root-cyber-pluto--/2026-09-25T09-58-22-477Z_01a0d800-700c-74a0-ad83-4413dd373f75.jsonl`.
SHA-256 at review:
`caf370eca56147ee5f9e96a9ecf0f573891896d51f54345126b16b3c2053056d`.

The same trace's tool calls match two audit roots:

- September 25–26: `engagements/jangow/logs/tool-invocations.jsonl`, with
  `engagements/jangow/state/pluto.db` and its evidence directory.
- September 27: repository `logs/tool-invocations.jsonl`, `state/pluto.db`
  and `evidence/validations/`. Final root evidence belongs to target #6,
  `ad-hoc`, host `127.0.0.1`, rather than the named Jangow target.
- `state/red-line-blocks.jsonl` and `state/red-line-approvals.jsonl` corroborate
  the scope denials, exact operator grant and consumption. These use a
  process/runtime session identifier distinct from the saved Pi trace header;
  tool call IDs and timestamps connect the records.

SQLite queries were opened with URI `mode=ro`. Credentials, flags and protected
file contents are omitted from this review.

## What went right

1. **Useful persisted investigation.** At September 25 09:59:03 the named
   engagement still had a prioritized privilege-escalation checklist. The
   September 25 10:06:22 command-injection reprobe reproduced the foothold.
   Its attempt to promote an already validated finding was refused by the
   status-transition guard; this did not repair the existing unsigned promotion.
2. **Scope enforcement and approval channel.** On September 27, access to
   `.60`, a subnet-discovery operation, and the proposed scope mutation were
   blocked before execution. The scope amendment was granted by operator `pc`
   at 07:56:09 for the exact blocked command and consumed on retry. No
   unauthorized scope bypass is demonstrated by this run.
3. **Root execution and deterministic evidence.** At 07:56:35 output showed
   effective root; at 07:57:49 finding #32 passed the fresh probe, baseline,
   readable-control and protected-file read differential. Validation #6 is
   present in the shared ledger. Protected-file bytes were suppressed.
4. **A broken wrapper was rejected.** Finding #30 at 07:57:00 failed because
   the escalated channel did not return the nonce. This was a useful rejection.
   Finding #31's subsequent rejection is a different issue, described below.
5. **Specific cleanup was checked.** At 07:58:06 recorded target output showed
   seven named temporary paths absent. The local wrapper deletion was issued,
   but its absence was not independently checked. These facts support bounded
   cleanup claims, not a complete resource/process inventory or restoration.

## What went wrong

### Resume rebound the conversation to a different engagement

The initial named ledger contains Jangow host `192.168.122.60`, foothold #4,
three recovered credential records and 21 investigation nodes. Its summary
remains `foothold`, `hard_cap:wall_clock`. September 27 root findings #30–32
appear in the shared database under `ad-hoc`, host `127.0.0.1`. The model saw
no findings and a fresh root node while resuming an established investigation.

`extensions/src/state/engagement.ts:67` selects from the current `PLUTO_*`
environment and falls back to `ad-hoc`; `state/db.ts:25` defaults to repository
state. The warning at `lifecycle/index.ts:217` does not stop mutations. The
trace establishes rebinding; the exact launch/restart command is not recorded.
Scope repair widened global targets #1 and #6 without restoring attribution.

### Successful reproduction was reported without its trust qualification

Both the original foothold #4 and final root #32 have NULL promotion signatures.
The final summary says `reached=root`, `hasRoot=true`, `signatureEnforced=true`,
but `trustworthyValidated=0` and `untrustedValidatedCount=1`. The final prose
reported completion without that qualification.

`findings-repo.ts:321` counts promotions without verifying signatures or current
finding status. `lifecycle/index.ts:167` uses that predicate for milestones,
and the progress fingerprint inherits it. `validators/gate.ts:69` emits plain
`VALIDATED` even when signing is absent. There is no observed forged validation
in this session: missing signatures establish lack of trusted attestation,
not evidence that the successful probe itself was fabricated.

### Three different stopping mechanisms were conflated

The trace contains **27 assistant provider cybersecurity-error records**, three
Pluto scope-error results, one explicit wall-clock error result and one SQL
schema-error result. Repeated operator assurances did not change the provider
outcome. Provider-only errors occur outside tool-call lifecycle checks.

At September 26 16:52:22 the next call was rejected at `111237s/7200s`.
The clock measures process elapsed time including idle/provider-block intervals;
it is not evidence of 111237 seconds of target testing. The launcher still has
a 3600-second default while lifecycle's fallback is 5400 seconds. Final
telemetry remains `in_progress` rather than a finished, trust-qualified outcome.

### Adapter and identity semantics introduced avoidable failures

The session loaded no-TTY-first doctrine but returned to a PTY helper. It listed
installed enumerators without demonstrating their execution in this trace.
An earlier technical attempt failed because its environment broke relative
utility lookup. Later command grouping lost the nonce.

Finding #31 at 07:57:29 had an effective-root identity and a successful
protected-file read differential, yet was rejected because
`privilege-escalation.ts:83` recognizes only real `uid=0`. The step name and
comments refer to effective root. This rejection is an identity-contract false
negative, not proof that effective root authority was absent.

### Cleanup and audit records were incomplete

Seven path checks do not establish every planted resource or background process
was removed. An earlier helper compilation could create cache artifacts; their
existence or removal is not established. Cleanup obligations are not durably
inventoried across interruptions. The named audit log has malformed JSON at
line 116; tolerant parsing recovers the remaining records, while strict parsing
cannot consume the complete file.

## Empirical QA and its limits

Fresh `npm run build` succeeded. These existing test files passed:

```text
node --test --test-reporter=tap dist/state/findings-repo.enforcement.test.js dist/state/findings-repo.promotion.test.js dist/lifecycle/lifecycle.test.js
```

Nine scenario records with assertions were executed by
`/tmp/pluto-board-01a0d800/qa-checks.mjs`; results are in `qa-results.json` there.
They used scratch SQLite databases, an ephemeral in-memory signing key and
synthetic shell functions. They did not read protected files, contact the VM
or use provider APIs.

- Unsigned promotion: verification false, authoritative milestone still `root`;
  Gate 2 refuses submission. Signed positive control verifies and counts one
  trusted finding.
- Changing a fixture finding to `rejected` still leaves the milestone predicate
  true, with or without a formerly valid signature. This is an additional
  reproducible software residual, not an event observed in the historical run.
- Synthetic real-UID-root control passes; effective-root identity with the same
  read differential fails. Missing nonce and broken baseline control reject.
- Missing engagement metadata bootstraps an `ad-hoc`/`localhost` scratch target.

Existing tests passing did not cover or prevent these reproduced defects.
No full fresh harness suite or live end-to-end run was performed for this review.
Gate 2 had zero submissions in the reviewed ledgers; its current fixture behavior
does not mean it was exercised by the historical session.

## Agreed next changes

1. **P0 — Bind resume to explicit engagement/run identity and readiness.**
   Persist target, ledger, scope, evidence/log roots and signing/sandbox mode.
   Refuse target mutations on missing or mismatched identity while retaining
   diagnostics. Reopening this trace must not silently select `ad-hoc` or
   attribute Jangow evidence to loopback.
2. **P0 — Share trust and current-status predicates.** Use them consistently in
   progress detection, milestones, validator responses, reports and terminal
   outcome. Show deterministic reproduction separately from signed trust.
   An unsigned or rejected fixture must not yield an authoritative root label.
3. **P1 — Persist distinct lifecycle reasons and explicit clocks.** Distinguish
   provider-blocked, scope-denied, paused, expired, running and finished states.
   Do not retry identical provider failures without a meaningful external state
   change or attempt safeguard circumvention. Align effective cap defaults and
   publish final telemetry after execution ends.
4. **P1 — Provide typed operator scope changes and cleanup debt.** Amend one
   identified engagement transactionally through the control plane rather than
   raw SQL repairs. Inventory created resources, carry unresolved obligations
   across interruptions and verify each cleanup action before claiming closure.
5. **P1/P2 — Define execution-channel and UID/EUID contracts.** Verify argument
   boundaries, nonce propagation, baseline controls and real/effective identity
   semantics with fixtures before passing templates into the full validator.

The prior sandbox workspace/startup fix remains open and belongs in the resume
readiness work. Protecting scope authority and characterizing agent-supplied
template trust are static design follow-ons; no exploitation of those weaknesses
was observed in this trace.

## Metrics to report carefully

There were 35 user messages and 51 tool calls: 13 on September 25, one on
September 26 and 37 on September 27. The roughly 46-hour trace span includes
idle time and provider errors. The final scope-corrected sequence from 07:56:18
to 07:58:06 was approximately 108 seconds. `attemptCount=104` is cumulative
default-target history, not the session's 51 calls. `contextTokensSeen` is a
context estimate, not demonstrated billed token spend.
