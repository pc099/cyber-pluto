---
name: pluto-review-board-process
description: Significant/architectural Cyber Pluto changes go through a 3-agent review board that huddles to consensus before implementing
metadata:
  node_type: memory
  pinned: false
  originSessionId: cd62bcb3-ff28-44ca-b538-364dcdb3abdc
  modified: 2026-09-17T04:14:49.697Z
---

For significant or architectural work on Cyber Pluto, the operator wants a
**four-agent review board**, not a solo decision:

1. A **harness-architect** agent (structure, Pi-fit, maintainability, mergeability).
2. A **cybersecurity** agent (the two gates, red-lines, isolation, attack surface,
   concrete bypasses).
3. A **griller** agent — an adversarial critic that pokes holes with concrete
   scenarios and pushes the simplest thing that works.
4. A **QA-tester** agent — empirical verification, not reasoning: it RUNS the
   change (reproduces the claimed behavior, runs the full test suite and the
   affected paths, exercises edge/boundary + failure cases), analyses test
   COVERAGE and where tests give false confidence, checks for REGRESSIONS, and
   confirms the implementation actually matches the spec/commit. The griller
   argues what *could* break; the QA tester finds what *did* break by executing.
   Give it tools (subagent_type "claude"/general-purpose, not read-only) so it
   can actually run tests and reproduce behavior against the lab/VulnHub targets.

The process the operator asked for:

- First **research concretely** so the board reviews a grounded proposal, not a
  vague question ("have concrete understanding before making the decisions").
- Spawn the three (they can read the repo; use `subagent_type: "claude"`), each
  returning a structured verdict (APPROVE / REWRITE-REQUIRED with concrete items).
- Then hold a **team huddle**: give each agent the other two's positions (and any
  new empirical result) and have them react to and discuss each other's points —
  "each agent's opinion is heard and discussed on, and then the decision is
  taken." Resume the same agents with SendMessage so they keep their context.
- **Only implement once the three converge / agree** on the approach; **rewrite
  changes if the board requires**. Relay the consensus (and the rewrites it
  forces) to the operator, don't just present three separate verdicts.

This has worked well in practice: the huddle produced a materially better,
hardened design than any single agent's opening position (e.g. it replaced a
Docker-container plan with a lighter UID-demotion + nftables owner-match egress
approach and independently caught a setuid `no_new_privs` bypass). Reserve the
full board for consequential/architectural changes; small, well-scoped fixes
don't need it, but do run it before shipping anything that changes the security
model, the harness architecture, or the run model.
