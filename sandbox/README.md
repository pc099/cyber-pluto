# Sandbox deployment and local readiness

Decision 0009 uses an independently deployed, root-owned runtime at
`/opt/cyber-pluto`. Development remains in `/root/cyber-pluto`; setup never
binds or recursively freezes that checkout. A manifest covers the selected
runtime, source extensions, compiled tools, production dependencies and Python
services. Source sessions, credentials and legacy state are excluded.

## Setup

Build the extensions first, then explicitly deploy an absent destination:

```bash
cd /root/cyber-pluto/extensions
npm run build
sudo /root/cyber-pluto/sandbox/setup.sh /opt/cyber-pluto
sudo /opt/cyber-pluto/cyberpluto 127.0.0.1 --label readiness --sandbox-check
```

Setup is offline: install prerequisites separately. It prepares the dedicated
`pluto` UID, protected directories and matching Ed25519 keys. Existing keys are
preserved and verified; partial or unsafe keypairs are refused. Setup never
starts a target engagement. `--sandbox-check` runs disposable local confinement
and signing fixtures with no Pi, model or target invocation. It does not test
the full extension profile or independently establish validation evidence.

All sandbox launches use the **canonical `/opt/cyber-pluto` runtime**, including
launches from the development checkout or an alternate deployment. Alternate
runtime destinations are staging/QA snapshots, not activation. Setup refuses
an existing destination. For an update, root must first verify no Pluto UID
workloads, launch lock, recovery hold or Pluto egress policy remain; preserve
and rename the old canonical runtime to an absent backup path, then deploy the
new snapshot at the canonical path and repeat readiness. Do not edit deployed
files or replace a runtime during a run. Saved sessions are association-bound;
this procedure preserves the canonical pathname, not an arbitrary relocation.

## Paths and controls

| Resource | Location |
| --- | --- |
| Writable workspace | `/var/lib/cyber-pluto/engagements/<label>/` |
| Session history | workspace `sessions/` |
| State, evidence and audit | workspace `state/`, `evidence/`, `logs/` |
| Pi agent configuration | workspace `pi-agent/` |
| Operator stop | `/var/lib/cyber-pluto/control/KILL_SWITCH` |
| Protected signer | `/run/cyber-pluto/signers/<label>/promotion.sock` |
| Exclusive launch lock | `/run/cyber-pluto/launch.lock/` |
| Unconfirmed cleanup marker | `/var/lib/cyber-pluto/control/RECOVERY_REQUIRED.json` |
| Private/public keys | `/etc/cyber-pluto/promotion_ed25519.key` / `.pub` |

The wrapper requires bubblewrap and drops to `pluto` with `no_new_privs`.
Host mounts and runtime are read-only, `/root` is masked, `/tmp` is private,
and the selected workspace is writable. Disabling bubblewrap is refused.
The public key must remain readable and visible inside the sandbox; the private
key is root-only and excluded from the agent environment.

The operator may stop a run with `sudo touch
/var/lib/cyber-pluto/control/KILL_SWITCH`. Confirmed `/kill` sends a bounded
monotonic stop request to the root signer; the daemon writes its configured
control path. The agent cannot choose another path or remove the sentinel.
Parent and delegate guards honor it. Clear a root stop only after inspecting
workloads and state; a UI stop is not proof that detached commands ended.

An nftables OUTPUT allowlist applies to Pluto UID traffic, allowing scoped
hosts, resolved provider addresses, loopback and the configured resolver.
Each table records a launch owner; a different launch cannot replace or remove
it. Launches serialize globally. After a production spawn attempt, cleanup stops
owned handles and retains the policy, lock and recovery marker because a process
inventory cannot prove that arbitrary descendants ended. Explicit root recovery
is required before another launch or resume: independently confirm quiescence,
inspect the recorded run owner and remove only its resources. Preserve session
descriptors, provider holds and trust qualification during recovery.
Controlled no-model readiness probes may remove owned protection after verified
process termination and observed UID quiescence. Unknown termination or cleanup
failure retains resources. Root must inspect and recover those resources; there
is no automatic stale-lock deletion or unconfined fallback.

## Resume and credentials

Fresh confined sessions can reopen with the same label, target, scope, canonical
paths and signing configuration using `--session <path-or-id>`. Preflight checks
the selected branch against its durable descriptor without rewriting history.
Historical bound-v1 sessions under `/root` cannot be relocated, converted or
adopted by this launcher. Preserve them; migration is separate work.

Provider holds persist across resume. Interactive diagnostics allow the operator
to use `/provider-retry <reason>` for one deliberate request while normal input
and tools remain held. A saved environmental pause can similarly reopen only a
valid same-association interactive session for `/unpause`; headless/readiness
starts cannot bypass it. Hard caps and protected root stops stay authoritative.

Supported API-key providers use explicit environment credentials. For
`openai-codex`, root reads only an existing private operator OAuth access token,
passes it through the environment and requires enough validity for the finite
wall cap plus five minutes. No refresh token, credential-file persistence or
automatic login is used. Expired credentials require operator refresh first.
The token remains visible to the agent that uses it; provider-channel isolation
is not claimed.

## Evidence and limits

The root signer pins the canonical ledger/ancestor identities and owns the key.
Strict sandbox mode routes all SQLite access through a persistent confined
unprivileged reader with a retained ledger handle, fixed queries and bounded
typed correlated IPC. The reader receives no keys or provider credentials.
Reader exit, timeout or invalid replies refuse service without root SQLite
fallback. Health signatures use a separate domain and bind the
ledger, launch, fresh challenge and verifying key. Stale sockets and replaced
ledgers are refused. Unsigned/directly flipped validated rows do not establish
verified current facts or Gate 2 eligibility.

**Forged passed-validation rows remain open:** the agent can write validation
rows and obtain a signature. Signing establishes provenance, not independent
evidence truth. Evidence, audit and outcome files remain mutable continuity data.
The reader shares Pluto's UID and is susceptible to same-UID manipulation; its
process and IPC are not an independent validation authority.

The mount scheme does not provide general host read isolation or confidentiality
between external engagements sharing the Pluto UID. Kernel escapes, detached
process supervision and persistent token/no-progress counters remain separate
work. Runtime service imports do not prove usable KB retrieval: legacy KB state
is deliberately excluded and its existing default is not provisioned in the
read-only runtime. Resolve KB provisioning before relying on retrieval in a
new evaluation. Local fixtures do not establish success on a target box.

## Explicit local QA

Build and deploy the canonical runtime first. Run these root-host fixtures
sequentially from the checkout; they refuse or preserve conflicting resources
and use disposable local data. The full-profile fixture uses an in-memory
provider and refuses network fetches. Boundary production payloads are fixed
local probes with synthetic credentials, so they make no provider requests.

```bash
sudo python3 extensions/test/sandbox-profile-qa.py
sudo python3 extensions/test/sandbox-startup-qa.py
sudo python3 extensions/test/sandbox-boundary-qa.py reader
sudo python3 extensions/test/sandbox-boundary-qa.py production
```

Production-retention checks intentionally retain owned policy/lock/marker,
verify refusal of another launch, then perform explicit fixture-owned recovery.
These tests do not authorize an engagement or provide general process supervision.
