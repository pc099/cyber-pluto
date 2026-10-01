# Decision 0009 — Current ICA1 assessment and next sandbox-readiness slice

Date: 2026-10-01. Operator request: check the next step with the board after
assessing the Pluto session. This decision records assessment and design, not
implementation, migration or a new target run.

## Board process and consensus

Architect, cybersecurity and griller were delegated as distinct reviewers.
The coordinating agent executed empirical QA as the fourth role. The tool's
thread limit rejected a fourth child even after an existing child completed;
this review therefore does not claim four independently delegated agents.
All four roles' positions and measured QA results were shared in a huddle.

Independent verdicts required a rewrite of the initial implementation contract
while agreeing on the priority. The rewritten proposal selected concrete
deployment/control paths, narrowed migration scope, specified fail-closed
readiness and defined protection on unknown process termination. The architect,
security and griller then APPROVED the revised design; coordinating QA APPROVED
that bounded direction. Their final acceptance wording and kill-path/health
protocol conditions are incorporated in the proposal.

**Consensus: APPROVE local sandbox/signing readiness as the next engineering
slice. No repaired sandbox, trusted target completion or cleanup is approved.**
The implementation contract is
`docs/proposals/sandbox-startup-readiness.md`.

## Latest session supersedes the old ICA1 handoff statement

The handoff described lab setup with no target engagement. Read-only inventory
during this review found a newer real Pluto session:

`engagements/ica1-test/sessions/2026-10-01T13-56-51-969Z_01a0f7c0-f080-72e9-87a0-1512c5ea1adf.jsonl`.

SHA-256 at review:
`6e9d8337062964ffe487663192d0b5f6a6602b612b158bad950c664ea795f30d`.
The transcript spans 13:56:51–14:06:27 UTC on October 1. Its one user message
explicitly authorized an unsandboxed ICA1 lab test, acknowledging unresolved
sandbox/signing readiness. No later operator recipe or recovery instruction
appears in this trace. The agent performed the subsequent technical sequence.

The session binding correctly identifies `ica1-test`, target `192.168.123.10`,
with explicit scope, canonical engagement roots, `sandboxMode=disabled` and
`signingMode=unsigned-configured`. This does not reproduce the old Jangow
ad-hoc/loopback attribution error. It does not establish an authority boundary.

Recorded results:

- 73 tool-call results and 73 attempts: 50 bash calls, six reads, five writes,
  two credential records, four explicit candidates, four validator calls and
  two investigation/finding-list calls. The ledger has eight findings total
  because recon created four additional candidates.
- Final finding statuses: four candidate, three rejected, one validated;
  two credential records, four validations and zero submissions. Secret values
  and protected-file contents are omitted from this decision.
- Both command-injection validations rejected. The first privilege-escalation
  candidate rejected; corrected finding #8/validation #4 passed. Recorded tool
  results show root identity, and the deterministic validator recorded its
  nonce/baseline/protected-file access differential. No target commands were
  replayed during this review.
- Finding #8's promotion signature is NULL and its tool result explicitly says
  `verified=false`. Summary correctly reports zero verified-current findings,
  no trusted foothold/root and `reached=candidate_found`. These trust-qualified
  fields do not erase the narrower recorded root reproduction.
- The run stopped at `hard_cap:tokens` after approximately 569 seconds.
  `contextTokensSeen=4001634` is a process-local context estimate, not measured
  billed token usage. No provider-block outcome is recorded. No final assistant
  completion narrative appears after the final blocked tool.
- The investigation tree contains 22 nodes, all active: one recon, four port
  investigations and 17 hypotheses. Meaningful technical activity was not fully
  reconciled into tree completion.
- Multiple upload/helper/account-mutation attempts and local credential-bearing
  artifacts create cleanup debt. Earlier individual removals are not a complete
  cleanup inventory. Durable outcome records execution and cleanup as unknown.

Accept **recorded autonomous technical progress and root reproduction after an
initial operator authorization**, qualified as unsandboxed and unsigned.
Trusted completion, confinement, target restoration and comprehensive cleanup
remain unestablished. Review cleanup/restoration debt separately before another
target evaluation; this review authorizes no target replay or cleanup action.

## Empirical QA performed for this review

No production implementation, real engagement state or firewall rules changed.
Temporary startup fixtures were removed after execution. No external model or
target was contacted.

1. Minimal host-context startup: `setpriv --no-new-privs --reuid pluto --regid
   pluto --init-groups -- bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs
   /run --die-with-parent --unshare-ipc --unshare-uts --chdir /tmp
   /usr/bin/true` exited zero. The tool-sandbox attempt failed at setresuid;
   the host-context execution was explicitly approved.
2. `/tmp/pluto-startup-board-qa.py` exercised the current wrapper with disposable
   engagements and a scratch copy of the wrapper, without applying egress or
   starting Pi. Actual results:

   | Check | Observed result |
   | --- | --- |
   | Current wrapper, scratch engagement under `/root/cyber-pluto/engagements` | Exit 1, `bwrap: Can't mkdir parents ... Permission denied` |
   | Current wrapper, workspace under `/tmp` | Exit 0, UID 994, no_new_privs=1, cwd remains development checkout |
   | Scratch wrapper/runtime and workspace outside `/root` | Exit 0; runtime write denied, workspace write allowed, root-only fixture read denied |
   | Scratch wrapper with `PLUTO_BWRAP=0` | Exit 0; demonstrates the current confinement fallback |

   The root-only file was synthetic, not a key or credential. The scratch runtime
   was not the deployed Pluto stack. These results reproduce the startup failure
   and establish a limited placement/confinement fixture, not full isolation,
   actual signing, dependency closure, resume migration or allowed/denied egress.
3. Targeted compiled regressions ran with `node --test --test-reporter=tap
   dist/launcher/launcher.test.js dist/state/session-binding.test.js
   dist/state/findings-repo.enforcement.test.js
   dist/state/gate1-forge-residual.test.js` from `extensions`: **30/30 passed**,
   zero skipped, in approved host context. Initial tool-sandbox execution passed
   three test files and failed the Unix-socket forge fixture; it was rerun outside
   that boundary. No fresh build or full suite is claimed for this documentation
   and assessment task.
4. The forge sentinel still confirms that forged passed-validation rows can
   receive signatures. Passing this sentinel means the residual remains OPEN.

## Ratified next slice and limits

- Independently deploy a sanitized root-owned runtime at `/opt/cyber-pluto` and
  writable engagements at `/var/lib/cyber-pluto/engagements/<label>`. Manifest
  runtime dependencies; avoid the existing bind-and-recursive-freeze setup that
  modifies the development checkout. Mask `/root` and give launches private
  temporary storage so copying the runtime does not expose source histories.
- Add no-model readiness checks before provisioning/resource side effects.
  Require bubblewrap and matching usable signing/verifying keys; refuse silent
  unconfined/unsigned fallback. Feed canonical paths consistently to signer,
  parent, child and delegates.
- Protect global kill control at `/var/lib/cyber-pluto/control/KILL_SWITCH`,
  wiring all parent/delegate guards, red-lines and operator command paths.
  Use stable protected signer sockets under `/run/cyber-pluto/signers/<label>`;
  domain-separate bounded ledger/launch-bound health signatures from promotion
  claims. Reject stale/unowned endpoints and substituted ledger paths.
- Serialize launches with a root-controlled global lock before shared-UID
  firewall changes. Track acquired resources, errors and signals. Keep restrictive
  egress plus a root recovery marker when workload termination is unknown; never
  remove another run's protection or equate direct-child exit with quiescence.
- First prove fresh-location sessions and unchanged-association resume, including
  delegate inheritance and retained holds. Preserve historical artifacts and
  refuse bound-v1 relocation/conversion before publication. The existing ICA1
  descriptor must not be silently rewritten, adopted or converted into signed
  sandbox history. No legacy runtime import is part of this slice. A separate
  coherent migration design must address WAL snapshots, source/signature
  preservation, branches/forks, outcome history, resolver semantics and rollback.

Actual repaired-stack QA must then execute confinement, real signing/verifying,
status-flip refusal, stop-control propagation, stable resume/holds, ledger/socket
substitution failures, concurrent launch refusal, staged failure/signal handling
and host-context uid-specific allowed/denied egress with root traffic unaffected.
No target evaluation follows automatically from setup or a readiness command.

Independent validation authority, evidence authenticity, full process supervision,
cleanup debt, execution-adapter/UID-EUID contracts, tree reconciliation and
persistent cap counters remain follow-ons. Closing the forged-validation path
must follow its separate decision; target I/O as root is not approved here.
