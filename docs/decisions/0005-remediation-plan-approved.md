# Decision 0005 — Remediation plan APPROVED WITH CONDITIONS (unanimous board)

All four members voted APPROVE-WITH-CONDITIONS on `docs/proposals/remediation-plan-0004.md`.
Consolidated, ratified conditions below. One cross-agent conflict resolved (see †).

## Increment 1 — `file_write_rce` validator (build first)

- **C1 (serializable, standalone).** No closure across the tool boundary. Register
  STANDALONE (like `validate_idor`), taking a **declarative write-request
  template** (method, URL, filename field, content field, multipart/auth shape);
  build the write internally. `record_candidate.vuln_class` does NO routing —
  don't add an enum; routing is which `validate_*` tool the core calls. Correct
  the plan's language.
- **C2 (prove exec safely — do NOT plant a backdoor).** Prove execution with an
  **inert arithmetic file** (`<?php echo "A".(7*7)."B"; ?>` → `A49B`, which the
  file's bytes cannot contain). Do NOT plant a `system($_GET[cmd])` shell. If
  host detail is wanted, a **fixed-command** `id` file (no parameter injection).
  Name every artifact from a **CSPRNG** (`crypto.randomBytes`), never
  `Math.random()`.
- **C3 (don't over-claim, don't drop).** RCE requires exec proof. A pure
  file-write with NO exec must NOT pass as `file_write_rce`, but the proven
  "file landed + served" signal records as a **separate lesser
  `arbitrary_file_write` finding** — not silently dropped.
- **C4 (clean baseline).** Capture the baseline for an unplanted canary
  (`pluto_<rand>` → 404) BEFORE any write. Fixes the self-poison false-negative.
- **†C5 (cleanup DECOUPLED from verdict).** `passed` reflects REPRODUCTION only.
  A cleanup FAILURE must NOT flip the verdict to not-passed (that reintroduces
  the Decision-0004 false-negative). Instead: validate on merits, raise a
  **blocking operator alert** (halt further tool execution until acknowledged),
  and log the exact artifact path + removal command as evidence in BOTH the
  success and failure branch. *(Resolves QA's "failed→not-passed" against the
  architect+cybersecurity decouple — decouple wins: 2 explicit votes + it is the
  whole point of Decision 0004.)*
- **Backfill (griller+QA).** Promote this run's RCE to `validated` ONLY via a
  LIVE re-run of the new validator against the still-reachable box, with FRESH
  nonces, through `findings-repo.promote` (gate not bypassed), cleanup recorded.
  If the box is gone, do NOT backfill — leave it `candidate`.

### Increment 1 tests (QA — must-have)
- PASS: both signals (file served + `A49B` exec) → `passed:true`.
- reject-safe (no write); reject-write-only → records lesser `arbitrary_file_write`, not RCE.
- **cleanup-happened:** the PLANTED `.php`/`.txt` return 404 after + fixture FS is clear.
- **cleanup-FAILED:** delete throws → `passed` STAYS true (repro proven) + a blocking-alert flag is set + `diffSummary` matches `/ARTIFACT MAY REMAIN/` + path logged. *(adjusted to the decouple)*
- **GATING TEST — baseline-before-plant:** an op-order spy asserts `baseline-get` precedes `write`, and the baseline body does NOT contain the content-nonce (the exact self-poison regression).
- Regression: keep `HOST_DETAIL` exported (cmdi test green); `GateReport`/`recordAndGate` changes additive/optional; leave `registerValidator`/`injectionParams` untouched.

## Increment 2 — disk-image scope rule

- Engagement-class-gated: BLOCK for network/black-box, ALLOW for forensics.
- Key on the **asset** (disk-image paths/content: `.vmdk/.qcow2/.ova/.img/.raw/.vhd/.vhdx/.vdi` + already-extracted trees), not just mount-tool names (a denylist leaks: `dd/binwalk/losetup/qemu-img/debugfs` + a plain read). Keep the tool denylist as defense-in-depth. Durable framing: "target knowledge must come from the network plane."
- Scope to OFFLINE attacker-host access — must NOT block Increment 1's HTTP writes to the live target.
- Tests: blocked (virt-ls/mount `.vmdk`), allowed (nmap/curl), alternative-tool (qemu-nbd/guestmount), uppercase/relative-path evasion, benign non-target `.img` allowed.

## Increment 3 — provisioning: STRUCTURAL, not doctrine

- Make launch-time provisioning structural (launcher classifies / operator declares the domain → run its `verify`, install on failure, BEFORE handoff). A briefing nudge is the same lever that already failed. Guard test: the briefing string contains the `provision_capability`-first directive.

## HARD GATE (griller's die-on) — separate track

Blocking the disk-image read is symptom management. **Black-box recon must be
DEMONSTRATED to find a vuln over the network** before the remediation is called
"done". Tracked as its own item, not folded into Increment 3.

## Order

Increment 1 → 2 → 3; Increment 4 (phase caps + honest run-summary) last. Each
independently tested + committed. Baseline 97/97 must not drop.
