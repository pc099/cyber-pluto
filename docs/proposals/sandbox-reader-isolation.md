# Sandbox signing reader and conservative teardown

Date: 2026-10-02. Follow-up to Decision 0009 implementation review.
Status: architect, security, griller and QA independently reviewed and then
APPROVED after a sequential four-role huddle. Final implementation and bounded
local acceptance APPROVED by all four roles; see Decision 0010 and
`progress/sessions/2026-10-02-sandbox-qa.md` for measured evidence and limits.

The operator requests sequential work on the 4 GB host. Extension tests run
with one worker; board roles review one at a time.

## Findings

The root signer currently opens agent-writable SQLite files. Read-only WAL
connections may create or update metadata. Checks before and after access
cannot prevent side effects between those checks, particularly when writable
ancestor directories are substituted. SQLite's final-component no-follow
handling does not constrain earlier path components. This is a source-grounded
failure scenario, not an empirically reproduced compromise.

Sources: [SQLite WAL documentation](https://www.sqlite.org/wal.html),
[SQLite Unix VFS](https://sqlite.org/src/artifact/410185df49),
[Linux open](https://man7.org/linux/man-pages/man2/open.2.html).

A single `/proc` inventory can miss a child born after enumeration if its
enumerated parent exits before inspection. Repeated samples improve observation
but do not prove arbitrary descendants have terminated. Production cleanup
must therefore keep protection when termination is unconfirmed.

Setup also accepted resource overrides that the canonical launcher ignored.
The scoped fix rejects conflicting overrides before provisioning or publication.

## Bounded rewrite

1. In strict sandbox mode, root never opens or queries SQLite. Start a persistent
   confined reader as the dedicated Pluto UID, with `no_new_privs`, before any
   arbitrary workload. It opens the fixed canonical ledger once, retains that
   handle, and performs only fixed readiness and claim queries. No caller SQL or
   file path is accepted. Exclude keys and provider credentials from its environment.
2. Use private, bounded request/reply IPC with explicit correlation. Root validates
   field types and limits, rechecks pinned ledger/ancestor identities, constructs
   canonical promotion and domain-separated health claims, and holds the private
   key. Malformed replies, identity conflicts, reader exit and timeout refuse
   signing/health. Keep the reader in the daemon's owned process group. Closing
   the daemon must not leave a reader running silently.
3. Retain legacy trusted local signing compatibility outside requested sandbox
   mode; requested sandbox refuses the old root SQLite path.
4. Set a monotonic arbitrary-workload-dispatched flag before the production
   spawn attempt. Afterwards, stop owned handles, retain acquired egress and the
   launch lock, and publish recovery requirements even after direct-child exit.
   Automatic production release awaits separately scoped process supervision.
   Controlled no-model readiness probes may exercise verified owned teardown.
   Another production launch or resume requires explicit root recovery that independently confirms
   quiescence and removes only the retained run's resources. Recovery preserves
   session descriptors, provider holds and existing trust qualification.
5. Preserve canonical association/socket/client paths and all historical records.
   No legacy migration, target engagement or provider call follows from this work.

## Acceptance

Execute confined reader UID/no-new-privileges, key and credential denial,
read-only runtime/control and private temporary storage checks. Verify cold WAL,
DELETE-to-WAL transitions, fresh signed claims, failed validation/direct-flip
refusal, and main/ancestor/sidecar/schema substitutions. Bound IPC size, type,
correlation and time; kill/stall the reader and confirm refusal and cleanup.

Run actual source-profile same-association resume, persisted holds, explicit
operator recovery, parent/delegate STOP and staged startup/signal checks.
Verify controlled readiness teardown, production protection retention and foreign
launch/resource refusal. Run affected regressions serially. Unit tests alone
do not establish repaired operation.

The writable passed-validation-row residual remains open. Reader isolation
protects root filesystem access; it does not independently establish evidence
truth. Full process supervision, saved-state migration and target cleanup debt
remain separately scoped.
The reader shares the workload UID. Its private pipe is a bounded transport,
not authority independent of an agent that can manipulate same-UID processes.
