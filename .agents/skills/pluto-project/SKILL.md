---
name: pluto-project
description: "Resume or work on the Cyber Pluto cybersecurity harness in /root/cyber-pluto using its imported Claude session, build skills, progress ledger and four-agent board. Applies to Cyber Pluto project work and status requests."
---

# Cyber Pluto project context

Work from `/root/cyber-pluto`. Read its `AGENTS.md`,
`progress/CODEX_HANDOFF.md` and the relevant current progress/decisions first.
The handoff preserves the latest Claude session's outcome and next task.

The repository's `.agents/skills/` contains the four original build skills:
`pluto-build`, `typescript-patterns`, `python-patterns` and
`cybersecurity-modules`. Read `pluto-build` for build tasks and select the
layer skills relevant to the requested work.

Read `pluto-review-board/SKILL.md` in that directory for consequential changes
or requested board review. Its four role files are in `.codex/agents/`.
Pass their instructions to delegated agents if native role selection is
unavailable. Do not claim previous agents' live contexts have been recreated.

For current engineering research and research-led fixes, use
`pluto-harness-research/SKILL.md` and `.codex/agents/pluto-harness-researcher.toml`.
The researcher uses inherited web tools and advises the existing four-role board.

This is project engineering context. Keep Pluto's target-testing runtime skills
separate, and report historical test results separately from checks run now.
