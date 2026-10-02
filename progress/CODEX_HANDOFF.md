# Cyber Pluto handoff to Codex

Imported on 2026-09-30 from Claude session
`cd62bcb3-ff28-44ca-b538-364dcdb3abdc`.

Source transcript (kept in place, not copied into the repository):
`/root/.claude/projects/-root-cyber-pluto/cd62bcb3-ff28-44ca-b538-364dcdb3abdc.jsonl`.
The existing local import registry already associates that transcript with
thread `01a0f305-5c9d-7773-97aa-85ed8b5ae2aa` (title:
"Pi agent reasoning loop integration"). This handoff loads its relevant history
and instructions; it does not recreate the prior agents' live contexts.

## Verified during import

- Repository: `/root/cyber-pluto`, branch `master`, HEAD `57c7dda`.
  The working tree was clean before these instruction additions.
- Four Claude build skills exist: `pluto-build`, `typescript-patterns`,
  `python-patterns`, `cybersecurity-modules`. Codex links point to the originals.
- No standalone Claude agent-definition files were found in the project's or
  user's `.claude/agents` directories. The board was defined by session prompts
  and `memory/pluto-review-board-process.md`. Its four roles are reconstructed
  as reusable Codex agent files, with the original process preserved as a reference.
- `engagements/jangow/state/pluto.db` and run-summary files are present.
  Target reachability and the saved finding's signature have not been verified
  by this import.
- `sandbox/run-sandboxed.sh` still binds the supplied engagement directory
  at the same absolute path and changes directory to the repository under `/root`.
  Sandbox startup has not been re-run during this import.

## Latest session outcome

On 2026-09-24, Claude committed the Jangow review fixes as `57c7dda`:
fact-based no-progress detection, no-TTY escalation doctrine, a 5400-second
default wall-clock cap, and rejection of junk credential evidence.
The session and commit report 151/151 tests passing at that time. This is
historical test evidence; the harness suite was not re-run for the import.

The session then attempted to resume Jangow with the sandbox on 2026-09-25.
Two startup errors were reported:

1. `bwrap: Can't find source path /root/cyber-pluto/engagements/jangow: Permission denied`
2. After the traversal adjustment:
   `bwrap: Can't mkdir parents for /root/cyber-pluto/engagements/jangow: Permission denied`

Claude reported locking `.env` to mode 0600 and adding execute-only traversal
to `/root`. Its final proposed harness task was to relocate sandbox engagement
workspaces outside `/root` (example: `/var/lib/cyber-pluto/engagements/<label>`),
migrate saved state, and coordinate the signing socket. That implementation
was not completed in the source session. The next review must examine repo
traversal as well as workspace placement; relocation alone is not yet proven
to resolve every startup dependency.

The last source-session response, on 2026-09-27, reported that the organization
had disabled Claude subscription access for Claude Code. This was a source
session account-access message. No import action in this Codex session has
been rejected or blocked.

## Next steps for the harness

**Latest resume update, 2026-10-02:** Decisions 0009/0010 bounded sandbox
implementation and local acceptance are COMPLETE. All four delegated board roles
approved after sequential review/huddle and independent empirical QA. The
operator requests one reviewer and one heavy task at a time on the 4 GB host;
extension tests now default to one worker. Canonical sanitized `/opt/cyber-pluto`,
writable `/var/lib` workspaces, protected signer/STOP controls, no-model readiness,
unchanged-association resume/holds and conservative production resource ownership
are implemented. Strict sandbox signing uses a persistent confined unprivileged
SQLite reader; root owns keys/signatures/control and performs no SQLite access.
Reader schema/IPC failures refuse; production dispatch retains owned firewall,
lock and recovery marker until explicit root recovery before another launch/resume.

Guarded deployed checks passed actual confinement/signing, all 13 source
extensions, cold WAL, resume/trust/provider holds, pause/retry/STOP/delegate paths,
startup SIGTERM and conflict refusal. Independent QA passed nine reader cases,
12 denied `/proc` alternate reads and both local production retention/recovery
fixtures. Fresh serial suites: extensions 234/234, Pi settings 58/58, actual SDK
9/9. Pi static checks and browser smoke passed; initial monorepo typecheck was
SIGKILLed, constrained retry exited 0 but peaked around 1.5 GB RSS. No target or
live provider call. Evidence: `progress/sessions/2026-10-02-sandbox-qa.md`.

**Resume here:** preserve the tested canonical runtime and historical ICA1
records. Next engineering work requires a separate board proposal for independent
validation authority/forged passed rows or stronger process supervision/recovery.
The reader shares Pluto's UID; signatures still do not establish evidence truth.
Bound-v1 migration, KB provisioning, persistent cap counters and ICA1 cleanup
debt remain open. Review cleanup debt before another target evaluation; no target
launch is authorized by readiness/setup. Root recovery must preserve descriptors,
provider holds and trust qualification. Do not restart the original build plan.

**Publication checkpoint, 2026-10-02:** The operator authorized committing and
pushing the verified changes, then testing a new box. Pi settings fix
`bc5378410` is committed and pushed to `pc099/pi` on `main`; this parent commit
records the sandbox implementation and that submodule reference. Pi's automatic
hook was skipped for this commit because its required check components had
already passed separately, including the constrained typecheck. An earlier hook
attempt restarted the unconstrained check and was explicitly stopped (exit 143).
Operator reported repeated workspace discovery timeouts; no cause was established.
Avoid broad discovery and repeated heavy checks. New target selection and scope
remain pending; no new target/provider call has occurred.

**Earlier assessment and board update, 2026-10-01:** Decision 0009 supersedes the
earlier no-ICA1-run statement below. Session
`01a0f7c0-f080-72e9-87a0-1512c5ea1adf` ran explicitly unsandboxed with correct
ICA1 engagement binding and no signing. Recorded root execution and finding #8's
deterministic privilege validation pass are supported, but its promotion is
unsigned and there are zero verified-current facts. It stopped at the token
hard cap after 569s; execution and cleanup remain unknown. This review replayed
no target commands. Architect/security/griller and coordinating empirical QA
completed a huddle approving the revised sandbox-readiness design. Actual QA
reproduced the /root bind-parent failure, passed limited relocated scratch
confinement checks, exposed disabled-bwrap fallback and passed 30 focused
launcher/binding/trust tests in approved host context. Full repaired sandbox,
signing integration and allowed/denied egress are not yet proven.

**Historical resume point, superseded by October 2 above:** implement `docs/proposals/sandbox-startup-readiness.md` under
Decision 0009: sanitized /opt runtime, /var/lib writable engagement and trusted
controls, mask /root/private tmp, fail-closed no-model readiness, protected stable
signer endpoint and owned global launch/firewall lifetime. First prove fresh
workspaces and unchanged-association resume with preserved holds/delegate guards.
Refuse bound-v1 session relocation/conversion before publication; retain ICA1
history unchanged. Separate migration, independent validation authority and full
process supervision remain open. Review ICA1 cleanup debt before another target
evaluation; readiness/setup never launches one automatically.

**Earlier lab setup update, 2026-10-01:** The operator-selected ICA1 VM is installed and running
on dedicated host-only `pluto-lab` at verified DHCP address `192.168.123.10`; HTTP
returns 200. Jangow definition/images were removed as requested, with historical
engagement/session records preserved. See `progress/ICA1_LAB.md`. At that setup
checkpoint no Pluto box test had started; the later session is assessed above.

**Update, 2026-10-01:** The operator's research-led task is complete for the three
board-approved reliability slices. See Decision 0008 and the dated research memo.
Strict verified-current predicates, post-UI transactional approvals, explicit
session associations, guarded bootstrap, delegate inheritance, durable provider
holds/recovery and generic Pi cancellation are implemented. Final extension suite
184/184, actual SDK integration 8/8, Pi focused 9/9 + affected 60/60, build/check
all passed. No live target or provider call occurred. The operator subsequently
authorized committing all pending changes on 2026-10-01; the parent submodule
reference now includes the Pi cancellation fix and nine-case test suite. The
portable patch remains available for the earlier Pi base in `patches/pi/README.md`.

Remaining next work is the Decision 0009 board-approved sandbox startup/workspace
implementation and full local confinement/failure checks, followed by independent validation authority
and process supervision. The forged passed-validation-row residual remains open;
the current promotion signs an evidence reference, not independently established
evidence truth. Outcome metadata is continuity data; cleanup/execution remain
unknown after provider settlement, and token/no-progress counters are still
process-local. No provider-access approval is established by this work.


**Update, 2026-09-30:** The operator supplied a later Pi trace,
`01a0d800-700c-74a0-ad83-4413dd373f75`. The board review in
`docs/decisions/0007-last-jangow-run-review.md` establishes observed September 27
root reproduction, but its promotion is unsigned and attributed to default
`ad-hoc`/loopback state. Named Jangow remains foothold/hard-cap stopped. The
priorities are now engagement/run binding and consistent trust/current-status
predicates, with sandbox readiness/startup still open. The steps below preserve
the earlier Claude handoff; use Decision 0007 for the current ordered backlog.

1. Reproduce and map sandbox startup locally without an LLM or target engagement.
   Bring a concrete workspace/state/socket migration proposal to the four-role
   board. Preserve confinement and signing behavior throughout the design.
2. Implement the agreed fix in small increments and verify saved-state resume,
   writable workspace versus read-only host paths, trusted signed promotion,
   and teardown on startup failure. Report any untested privilege boundaries.
3. Then evaluate the repaired harness on the operator's authorized lab target,
   separating autonomous results from operator assistance. Target availability
   must be checked at that time; session IPs are historical.

Other recorded follow-ons: forged passed-validation rows still require a
stronger trusted validation path, and detached commands can overrun the cap
between per-call checks. Provider claims and the September 14 project-context
snapshot are historical; later code/session records supersede them.

## Preserved operator preferences

Use the four-agent board for consequential changes and let the members discuss
each other's positions before deciding. QA runs the affected behavior and
checks regressions; the griller challenges assumptions. Be empirically honest:
no fabricated completion, no root claim inferred from narrative alone, no
"tamper-proof" claim while a known forge path remains. Keep the operator posted.

## Import validation

All five build/review skills passed the skill-creator validator. All four agent
TOML files parsed and passed required-field checks. Both preserved memory
references match their sources after trailing-whitespace normalization, and the transcript SHA-256 matches
the existing import registry. Skill links resolve to the original Claude files.
A sixth skill, `pluto-project`, provides discovery from the session's `/root`
working directory and is validated alongside the five imported skills.
These checks establish artifact integrity, not a live target solve or proof
that a client UI has already refreshed its skill/agent selectors.
