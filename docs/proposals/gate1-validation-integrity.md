# Proposal: Gate-1 validation integrity (the Item-0 follow-on)

**Status:** DRAFT for board huddle. Not ratified, not built.
**Context:** Item 0 (committed `f0cf4c6`→`3e67f15`) closed the *direct status-flip*
forge — a raw `UPDATE findings SET status='validated'` is now inert because a
`validated` finding needs a root-signed promotion and consumers refuse an
unsigned/invalid one at Gate 2. This proposal addresses the **residual Item 0
explicitly left open.**

## The residual, precisely

The root signing daemon (`promotion-sign-daemon`) re-verifies, before signing,
that the referenced `validations` row exists, belongs to the finding, and has
`passed = 1`. But the **`validations` table is itself `pluto`-writable**, and the
entire validation write-path runs *inside pluto's realm* (`validators/gate.ts`:
the validator captures baseline/attack exchanges, computes `passed`, writes the
evidence files, inserts the `validations` row, then calls `promote()`).

So a hijacked agent does not need the direct flip. It can:

1. `INSERT INTO validations (finding_id, validator, passed, …) VALUES (…, 1)`
   — forge a *passed* validation row (and forge the evidence files it points to);
2. ask the daemon to sign the promotion — the daemon sees a `passed=1` row that
   references the finding, re-derives the claim, and **signs it**;
3. now hold a *legitimately signed* `validated` finding that no consumer check
   can distinguish from a real one.

**Root cause:** the ground truth of a validation is the **network interaction
with the target** (baseline request, attack request, differential compare). That
interaction, and the pass/fail decision over it, currently happen where pluto can
fabricate them. Signing a claim about a forgeable row cannot fix a forgeable row.

This makes Gate 1 tamper-**evident** (Item 0) but not tamper-**proof**. Closing
it means making the `passed` verdict itself unforgeable by a pluto-level attacker.

## Design constraints (what any fix must respect)

- **Scope safety must not regress.** The current safety spine is the nftables
  `meta skuid pluto` owner-match egress allowlist: only `pluto`-owned packets are
  filtered to in-scope targets; **root egress is unrestricted.** Any design that
  makes *root* talk to the target moves target I/O outside the egress allowlist —
  a potential *net safety loss* (out-of-scope reachability, no rate discipline).
- **Keep offensive decisions out of root.** "Exploration is free; consequences
  are gated" — the aggressive, creative attack logic should stay in pluto. Root
  should faithfully *record/recompute*, not *decide to attack*.
- **Blind/OOB classes (§4.7)** confirm via a correlated out-of-band callback, not
  a same-request diff — any evidence model must accommodate them.
- **Determinism (§4.5).** Gate 1 is non-LLM: pass/fail is a deterministic
  function of captured evidence. That is the property a privileged party could
  in principle *recompute* — if it can trust the evidence.
- **Non-breaking + incremental**, like Item 0: fall back to today's behavior when
  the privileged path isn't configured; land in committed, tested slices.

## Options (for the huddle)

### Option A — Privileged re-validation (root re-runs the check)
Root, given the candidate + validator class + params, independently re-executes
baseline→attack→compare against the target and signs the validation iff it agrees.
- **Pro:** genuinely tamper-proof for network-observable classes.
- **Con (serious):** root now performs **target network I/O**, which bypasses the
  pluto owner-match egress allowlist — a scope-safety regression, and it
  reintroduces offensive execution as root. Would need root egress *also* scoped
  (a second firewall model) + the validator logic runnable under root. Highest
  cost; arguably trades one safety property for a worse one.

### Option B — Privileged capture proxy (root records, root recomputes)
All target traffic flows through a **root-controlled recording proxy** that writes
**append-only, root-owned** evidence. pluto still *chooses* the requests; the
proxy just faithfully records the real exchanges. The `passed` verdict is
**recomputed by root** from that trustworthy evidence and signed.
- **Pro:** attack decisions stay in pluto; root only records + recomputes;
  evidence becomes unforgeable; egress model unchanged (pluto still originates).
- **Con:** a real MITM/proxy for arbitrary protocols is complex; TLS interception;
  blind/OOB classes don't flow through an HTTP proxy (need the OOB server as the
  trusted recorder instead); recompute logic must live root-side per class.

### Option C — Human evidence review at Gate 2 as the compensating control
Accept the residual for the *autonomous* path (Item 0 already makes forgery
tamper-evident and forces it through the auditable signed path), and rely on the
**Gate-2 human** — who already must approve every external submission — to review
the signed evidence chain before anything leaves. Frame autonomous `validated` as
*advisory*; the human is the true integrity gate for external consequences.
- **Pro:** no new attack surface; matches the existing compliance gate; the
  externally-consequential path (submission) is already human-gated. Cheapest,
  and honest about where machine trust actually ends.
- **Con:** does not give the *agent itself* a trustworthy internal signal (it can
  still waste effort on a self-forged `validated`); relies on human diligence.

### Option D — Hybrid (recommended starting point for discussion)
**C now, B next, A rejected.** Ship C as the honest, documented posture
immediately (it's mostly wording + a Gate-2 evidence-review checklist + surfacing
`listUntrustedValidated`). Scope B as the medium-term tamper-proofing for the
network-observable classes, with the OOB server as the trusted recorder for blind
classes. Reject A unless the root-egress-scoping problem is solved first, because
it risks a net safety loss.

## Open questions for the board

1. Is the residual primarily a **safety** issue (external consequence) or a
   **robustness** issue (agent self-trust)? If the former, Option C may fully
   suffice given Gate 2 is already human. (Griller: attack this.)
2. Does Option A ever make sense, or is root-touches-target a hard no on scope
   grounds? (Cybersecurity + harness-architect.)
3. For Option B, what is the minimum viable trusted recorder — an HTTP(S) proxy
   only, plus the existing OOB server for blind classes? What about raw-TCP
   service exploits (not HTTP)? (Harness-architect.)
4. What does QA need to prove a fix actually closes the forge — a red-team script
   that forges a `passed` validations row + evidence and demonstrates it can no
   longer reach a signed, submittable `validated`? (QA-tester.)

## Non-goals

- Not re-opening Item 0 (the direct-flip fix stands).
- Not the MCP bridge, not new tools — this is core-invariant integrity only.
