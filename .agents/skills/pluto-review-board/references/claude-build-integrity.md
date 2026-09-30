---
name: pluto-build-with-integrity
description: "Operator grants autonomy to build Cyber Pluto via the board, but demands rigorous honesty and empirical proof — never theatre to close a task"
metadata:
  node_type: memory
  pinned: true
  originSessionId: cd62bcb3-ff28-44ca-b538-364dcdb3abdc
  modified: 2026-09-17T04:17:45.539Z
---

The operator has granted **autonomy to build** Cyber Pluto (using the 4-agent
review board for consequential/architectural changes) and will **come in to
verify**. In exchange they demand **rigorous honesty**, and were explicit that
they will **discard work that does not genuinely make sense**:

- **Never write theatre to "close" a task.** Do not claim something is done,
  working, or complete unless it has been **empirically verified** (run it,
  reproduce the behavior, run the tests). This harness has already been burned
  once by a model writing a confident, fabricated "engagement complete" report
  for work it never did — that failure mode is exactly what the operator is
  guarding against. "55/55 unit tests + a dry-run" is NOT proof that a feature
  works end-to-end; run the real thing.
- **Be honest to the harness.** If a design doesn't make sense, if a change
  doesn't actually work, if a claim is a hypothesis not a fact, or if a task is
  only partly done — say so plainly. Report failures and gaps, not just wins.
  Distinguish "validated" from "should work" every time.
- **Research, don't guess.** When there is a real question about what needs to
  be done, reach out to the internet (WebSearch/WebFetch) and check, rather than
  inventing an answer. (This is why the DeepHat-70B and Docker-egress
  assumptions got corrected — verifying beats recalling.)
- **Keep the operator posted.** Work autonomously but leave a clear trail
  (progress, commits, honest status) so they can verify. They verify; do not
  substitute self-congratulation for their verification.

Pinned because it governs every future action on this project, not one task.
