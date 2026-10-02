# Decision 0010 — Confined signing reader and conservative production cleanup

Date: 2026-10-02. Follow-up to Decision 0009 implementation review.

All four roles were delegated separately, with sequential huddle turns after the
operator requested lower concurrency on the 4 GB host. Architect, security,
griller and QA APPROVED the bounded rewrite in
`docs/proposals/sandbox-reader-isolation.md`. After implementation, independent
QA executed the affected boundaries; architect, security and griller inspected
the code, measured report and other positions sequentially. All four APPROVED
the bounded implementation and local acceptance. This does not approve target
operation or establish independent validation authority.

Strict sandbox signing must move SQLite access out of root into a persistent
confined unprivileged reader with a retained fixed ledger handle and bounded
typed correlated IPC. Root retains keys, pinned identities, canonical signatures
and protected STOP authority. Reader failures refuse service without fallback.
Writable passed-validation rows remain forgeable; this change does not establish
independent validation authority or evidence truth.

Production dispatch makes descendant termination uncertain under current process
supervision. Set a monotonic flag before the spawn attempt and retain acquired
egress, launch lock and recovery requirements on every later termination path.
Explicit root recovery is required before another production launch or resume,
preserving descriptors, holds and trust. Controlled no-model readiness probes may
verify owned teardown. `/proc` snapshots are observations, not release authority
after arbitrary workloads.

Canonical setup override conflicts now refuse before provisioning. QA executed
five refusal cases and shell syntax checks; canonical resource metadata and the
scratch deployment destination remained unchanged. Coordinating work rebuilt
extensions and ran the pre-rewrite serial host suite: 227/227 passed, zero skipped.
Those initial checks did not prove the rewrite. Final acceptance evidence is
recorded below. No target or live provider activity occurred.

## Final local acceptance

See `progress/sessions/2026-10-02-sandbox-qa.md` for commands, ownership, measured
results and attribution. Delegated QA ran nine actual confined-reader cases,
including UID 994/no_new_privs/credential denial, root SQLite constructor refusal,
twelve denied alternate `/proc` reads, reader kill/stall/daemon death, and ledger,
ancestor, sidecar and schema substitutions. The earlier deployment's view
acceptance was reproduced, then refused after the ordinary-table guard deployed.

Both fixed local production payload cases retained matching owned egress, root
lock and 0600 recovery marker. Another launch and foreign teardown refused.
Explicit fixture-owned root recovery preserved ledger/continuity artifacts.
The missing-payload case is an execution failure, not an injected OS spawn error.

Coordinating QA deployed the guarded canonical runtime and executed confinement,
synthetic signed promotion/direct-flip/failing-validation refusal, cold WAL,
all thirteen actual source extensions, same-association resume/trust/provider
holds/pause recovery, explicit retry, root STOP/delegate guards, unchanged legacy
relocation refusal, concurrent lock/stale endpoint refusal and signer-start
SIGTERM cleanup. Model responses came only from an in-memory provider.

Fresh build, serial extensions **234/234**, affected Pi settings **58/58**, and
actual SDK recovery/auth **9/9** passed. Pi static checks passed. The initial
whole-monorepo typecheck was SIGKILLed; its constrained retry completed exit 0
with `GOMAXPROCS=1 GOMEMLIMIT=768MiB`, but reached roughly 1.5 GB RSS. Browser
smoke passed separately. The Go target is soft; these are separate successful
components after a failed initial aggregate check.

Same-UID reader manipulation, writable passed rows/evidence truth, saved-state
migration, general process supervision/recovery tooling, KB provisioning and
ICA1 restoration/cleanup debt remain open. No live engagement follows automatically.
