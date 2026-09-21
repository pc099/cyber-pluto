# Remediation plan for the first-run findings (Decision 0004)

**Status:** DRAFT for board approval. Implements the ratified fix priority from
`docs/decisions/0004-first-live-run-review.md`. Built in small, tested,
committed increments; each ends green (current baseline 97/97).

## Increment 1 — `file_write_rce` Gate-1 validator + artifact cleanup (the #1)

**Why:** Pluto exploited an arbitrary-file-write→RCE but Gate 1 could not count
it (no validator for the class; the `command_injection` validator was mis-applied
with a self-poisoned baseline). And it left a live backdoor (no cleanup).

**Build:**
- New `extensions/src/validators/file-write-rce.ts`, same shape as `sqli.ts`/
  `command-injection.ts` (deterministic, non-LLM, baseline vs attack, technical
  signal + impact artifact, per-run nonces):
  - **Inputs:** a `write(path, bytes)` primitive closure (how the finding places a
    file), `fetchUrlTemplate` (where written files surface, e.g.
    `http://T:81/{name}`), optional `execHint`.
  - **Baseline (clean, captured BEFORE any plant — fixes the self-poison bug):**
    GET the canary URL for `pluto_<rand>` → assert 404/absent.
  - **Technical signal (write landed):** write `<nonce>.txt` containing a
    content-nonce; GET it back → body contains the content-nonce (absent from
    baseline). Proves an attacker file reaches a served path.
  - **Impact artifact (execution):** write `<nonce>.php` =
    `<?php echo "A".(7*7)."B"; ?>` → GET → body contains `A49B` (arithmetic the
    file can't contain literally); OR a `system($_GET[c])` shell with
    `c=echo <execNonce>;id` → body contains `<execNonce>` AND `uid=\d+\(`.
  - **Pass = technical signal AND impact artifact.** Reuse the exact `HOST_DETAIL`
    regex from `command-injection.ts` for the `uid=` clause.
  - **CLEANUP (mandatory):** in a `finally`, delete every planted artifact (the
    `.txt`, `.php`, and any shell) via the write primitive or the shell (`rm`),
    then GET the canary again → assert 404. Record cleanup in `diff_summary` /
    evidence. A validator that cannot confirm cleanup returns not-passed with a
    loud "ARTIFACT MAY REMAIN" note rather than silently leaving a backdoor.
- Register `validate_file_write_rce` in `validators/index.ts`; add `file_write_rce`
  (and `file_upload`) to the accepted `vuln_class` values so `record_candidate`
  routes to it, not `command_injection`.
- **Tests** (`file-write-rce.test.ts`, both paths + cleanup + clean baseline):
  a hermetic in-process HTTP+FS fixture with a real write primitive → PASS with
  both signals AND the canary is gone afterward; a safe (no-write) endpoint →
  reject; a write-but-no-exec endpoint → reject (technical signal only);
  assert the baseline is captured before planting (not self-poisoned).

**Done when:** 97→~101 tests green; then (operationally) re-run the validator
against this engagement's RCE to produce a real `validated` row + signed
promotion, proving the scoreboard now counts a genuine compromise.

## Increment 2 — close the disk-image scope hole (red-lines)

**Why:** discovery "cheated" by reading the target's local VMDK offline; that is
not black-box network testing and is a scope breach.

**Build:** a new red-line rule `local_target_artifact_access` (category) that
blocks, pre-exec, any offline access to a target disk/image: `virt-ls`,
`virt-filesystems`, `virt-cat`, `guestmount`, `qemu-nbd`, `mount … .qcow2/.vmdk/
.ova/.img`, and reads of files under `*/vulnhub/*`, `*.vmdk/.qcow2/.ova`. Reason:
"engagement is black-box/network — inspecting the target's disk image offline is
out of scope." Test both a blocked case and that normal network recon is allowed.

## Increment 3 — make enumeration tools actually get used

**Why:** `provision_capability` never fired; the agent hand-rolled curl and burned
the token cap. Tools are now installed (`ffuf`/`gobuster`/`whatweb`, Decision
0004) and in the `web` manifest.

**Build (light):** strengthen the launch briefing / recon skill so the FIRST
enumeration step is `provision_capability("web")` (verify the toolset) then
`ffuf`/`gobuster` for content discovery BEFORE any hand-rolled curl loop. No new
mechanism — a doctrine nudge + the manifest already updated.

## Increment 4 — caps + honest run-summary (lower priority)

Phase-aware token budgeting (enumeration vs exploitation vs post-ex) so recon
can't starve privesc, and a `/summary` (or report addendum) that surfaces
candidates + recovered credentials so a real foothold isn't hidden behind a
headline "0 validated". Deferred behind 1–3 unless the board wants it sooner.

## Sequencing

Build **Increment 1 first** (it's the board's unanimous top fix and closes both
the scoreboard gap and the live-backdoor failure), commit, then 2, then 3.
Increment 4 last. Each increment is independently tested + committed.

## Open questions for the board

1. Increment 1: is the arithmetic-echo (`A49B`) enough as the impact artifact for
   a *pure* file-write (non-PHP-exec) case, or must exec always be required to
   call it "RCE" (vs a lesser "arbitrary-file-write" finding)? (Cybersecurity/QA.)
2. Cleanup: if cleanup FAILS, is "return not-passed + flag" right, or should the
   finding still validate but with a blocking operator alert? (Cybersecurity.)
3. Increment 2 scope rule: any legitimate reason Pluto would read a local disk
   image (forensics-class engagements?) that this rule would wrongly block, and
   should it be engagement-class-gated? (Architect/Griller.)
4. Is the doctrine-only fix for Increment 3 enough, or must provisioning be
   structurally forced at launch? (Architect.)
