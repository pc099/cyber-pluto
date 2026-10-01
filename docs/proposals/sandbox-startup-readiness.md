# Sandbox startup readiness after the Pluto session assessment

Date: 2026-10-01. Ratified design under Decision 0009 after independent reviews,
four-role huddle and coordinating-agent empirical QA. No sandbox success is
implied. No new target
engagement or model call is in scope.

## Evidence and problem

Decision 0007 accepted recorded operator-assisted root reproduction, but not
trusted completion: final evidence was unsigned and attributed to ad-hoc state.
Decision 0008 implemented verified-current predicates, explicit session binding
and provider interruption handling. Its local software checks did not exercise
sandbox startup. The handoff's ICA1 statement is now stale: session
01a0f7c0-f080-72e9-87a0-1512c5ea1adf ran on October 1, explicitly authorized
unsandboxed, from 13:56:51 through 14:06:27 UTC. Its recorded root reproduction
and passed privilege validation are unsigned. It has zero verified-current
facts and stopped at hard_cap:tokens; execution and cleanup are unknown.

The historical sandbox failed to bind an engagement under /root. Current
inspection finds /root mode 0701, repository mode 0755, and no deployed
/opt/cyber-pluto or /var/lib/cyber-pluto. The wrapper still drops uid before
bwrap, binds the engagement at the same absolute path and uses the repository
as cwd. Both workspace parents and runtime traversal therefore matter.

Current code also permits a dropped-uid fallback when bwrap is absent or
PLUTO_BWRAP=0, warns and continues when the signing key is absent, waits for
socket existence rather than a usable signer, recursively chowns the workspace,
and cleans up mainly on child exit. The signer receives plan-relative state
paths while the child receives canonical paths. Session associations compare
exact canonical roots, signing-reference strings and sandbox mode. A directory
copy is not a resume migration. v1 signatures cover evidence-reference strings;
rewriting these strings invalidates old signatures.

## Proposed bounded next step

1. Repair sandbox readiness before further target evaluation. Deploy an
   independent sanitized root-owned runtime at /opt/cyber-pluto, with explicit
   writable /var/lib/cyber-pluto/engagements/<label> roots. Do not loosen /root
   permissions or run the existing bind-and-recursive-freeze setup on the
   development checkout. Define and manifest the runtime closure: Pi bundle
   and dependencies, launcher, source/dist needed by the configured profile,
   runtime skills and Python services/interpreter paths. Exclude .env, operator
   histories, engagements and development-control files; reject dependencies
   or symlinks resolving back into /root. Credentials are supplied by the root
   launcher. Pass identical canonical roots to parent, signer, child and
   delegates. Runtime cwd and signer command paths remain stable across resume.
   Mask /root in the child's mount namespace and use private per-launch /tmp;
   a sanitized /opt copy alone does not hide a readable source checkout through
   the current whole-host read-only bind. Verify direct source-history paths
   cannot be read. This is not a claim of general host read isolation.
2. Provide a no-model readiness entry point. Validate runtime traversal, uid,
   bwrap capability, safe workspace ancestors/ownership, matching signing and
   verifying keys, selected session/branch association and persisted holds
   before provisioning or launch side effects. Requested sandbox mode fails
   on unavailable/disabled bwrap or unusable signing; no silent unsigned or
   unconfined fallback. Strip private-key settings from child/delegate env.
   Keep global operator control beneath root-owned ancestors, at
   /var/lib/cyber-pluto/control/KILL_SWITCH. Wire PLUTO_KILL_FILE consistently
   through parent/delegate guards, red-lines and operator console commands;
   changing only one hook would leave hardcoded cwd controls inconsistent.
   Mutable workspace pause/provider
   metadata remains continuity data, not privileged authority.
3. Bound the first slice to fresh workspaces and unchanged-association resume.
   Inventory and preserve historical source state/logs/evidence/transcripts,
   descriptors, outcome journals and checksums. Refuse relocation or conversion
   of already bound v1 sessions, including the latest unsandboxed ICA1 session,
   before destination publication or target mutation. Directory copying,
   --adopt-session and descriptor edits are not migration. No legacy runtime
   import is claimed in this slice. Review a separate versioned migration
   design for selected branches, fork lineage, signed-reference resolution,
   consistent SQLite/WAL snapshots, existing holds, conflict rejection and
   rollback. Never rewrite signed evidence-reference strings to make paths fit,
   infer authority from narrative or convert unsigned history into trusted facts.
4. Put the stable signer socket at
   /run/cyber-pluto/signers/<label>/promotion.sock under root-owned ancestors,
   explicitly exposing that directory read-only after the wrapper's /run tmpfs.
   Use root-controlled endpoint ownership and a bounded signed readiness
   challenge tied to the expected canonical ledger and this launch. Reject
   use of the promotion signing domain for health checks; domain-separate
   readiness claims and never expose arbitrary caller-selected signing bytes.
   Reject
   unrelated existing endpoints rather than unlink them. Define refusal of
   symlink/path replacement for signer ledger access; canonical names alone do
   not pin the agent-writable database. Database row/evidence authenticity and
   the forged passed-validation-row residual remain open; no root target I/O.
5. Treat startup as an owned resource transaction. Acquire a global root launch
   lock at /run/cyber-pluto/launch.lock before modifying the shared uid firewall;
   register cleanup before resource creation. Handle staged failures, spawn
   errors and signals, and remove only acquired resources. Confirm confined uid
   workloads terminate before removing egress protection. If termination is
   unknown, retain restrictive egress and publish a root-owned recovery marker
   that blocks the next launch, rather than remove protection or claim cleanup.
   General process supervision stays separately scoped. Never replace another
   run's table or release protection merely because direct Pi exited.

## Acceptance checks

QA first reproduces local startup dependencies and fallback behavior with
scratch fixtures. Report restrictions of the active execution environment.
Implementation acceptance then requires an actual confined process, not a
dry-run: pluto uid/no_new_privs; runtime write denied; workspace writes succeed;
private key/control stop writes denied; usable public verifier and signer;
source history inaccessible and temporary files confined to this launch;
signed promotion passes and direct status flip fails; delegate inheritance;
explicit resume finds the same ledger and preserved provider hold; bound-v1
relocation/conversion is refused before publication, preserving source
signatures and holds; same-association resume retains trust qualification;
wrong/stale/missing configuration fails before
agent execution; startup failure/signal tears down owned resources; another
launch cannot displace protection. Real uid-matched allowed/denied egress and
root traffic unaffected must be tested in an authorized host execution context.

Independent validation authority (forged passed rows), evidence-content
authenticity, typed scope amendments, UID/EUID validator contract, cleanup debt
and full process supervision remain open. No test here establishes an
autonomous foothold-to-root solve or restored target state.

## Primary-source grounding

Bubblewrap protection depends on caller-selected arguments; it creates an
empty mount namespace and constructs the visible filesystem explicitly:
https://github.com/containers/bubblewrap#sandbox-security and
https://github.com/containers/bubblewrap#usage.
SQLite's backup API supports consistent database snapshots rather than an
uncoordinated copy of a live database: https://www.sqlite.org/backup.html.
These sources guide the proposal; local execution must establish host behavior.
