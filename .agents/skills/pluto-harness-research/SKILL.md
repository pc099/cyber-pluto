---
name: pluto-harness-research
description: "Research cybersecurity pentesting harness engineering for Cyber Pluto using current primary web sources and recorded failures; turn findings into four-role board proposals and verify approved fixes. Use for requested harness research and research-led hardening, not target exploitation."
---

# Pluto harness engineering research

Read `AGENTS.md`, `progress/CODEX_HANDOFF.md`, current progress and relevant
decisions in `/root/cyber-pluto`. The reusable researcher role is
`.codex/agents/pluto-harness-researcher.toml`. Pass its instructions to a delegated
agent when native role selection is unavailable. Inherit web tools and permissions;
the role cannot grant additional access or override provider safeguards.

Ground research in the affected source code and recorded evidence. Search primary
sources: official engineering documentation, original research, benchmark owners
and maintained project repositories. Verify current product/access claims.
Use the OpenAI Docs skill for OpenAI-specific research. Avoid reproducing secrets
or historical attack payloads unnecessarily.

Write dated research in `docs/research/` with direct links, source dates when
available, evidence limitations and the distinction between demonstrated behavior,
vendor claims and inference. Compare approaches only where they change Pluto's
engineering choices; do not copy third-party implementations or create a feature
backlog from marketing claims. Explicitly separate authorized-access options from
recoverable provider interruption handling.

Map each recommendation to a recorded defect, affected files, a bounded change
and observable pass/reject acceptance checks. Mark broader field directions and
deferred work separately. Use `.agents/skills/pluto-review-board/SKILL.md` for
independent review and a huddle before consequential implementation. The researcher
advises; it does not replace any of the four board roles. Keep research conclusions
separate from board approval and test evidence.

When implementation is assigned and authorized, build only the approved scope,
execute meaningful local checks and update decisions/progress. Distinguish local
fixture verification from sandbox-boundary proof and live engagement results.
Research authorization alone does not authorize external submissions, provider
access applications, paid model calls or new target operations.
