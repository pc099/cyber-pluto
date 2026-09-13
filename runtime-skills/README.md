# Pluto Runtime Skill Catalog (Architecture §6.5)

These are Pluto's **runtime doctrine skills** — hand-authored expertise the
reasoning core auto-selects *during an engagement*. They are **distinct from
the build skills** in `.claude/skills/` (which guide Claude Code building
Pluto) and from the **knowledge base** (`services/pluto_services/kb`, which is
data that grows automatically). A skill configures *how the agent approaches a
class of task*; the KB answers *what we know about this target/CVE* (§6.5).

## Loading

Each skill is a directory containing `SKILL.md` with Agent-Skills frontmatter
(`name`, `description`). Pi auto-selects a handful per task from the
`description`. Load the catalog for an engagement with:

```
pi --skill runtime-skills   # discovers every SKILL.md recursively
```

They are **not** auto-loaded in build sessions (they live outside `.pi/skills`
and `.agents/skills` on purpose), so Pluto's runtime doctrine never leaks into
Claude Code's build context.

## Structure (§6.5.1)

Built out across five categories, scoped to Pluto's CTF + web bug-bounty
targets:

- **vulnerabilities/** — one per core class (aligns 1:1 with the Gate 1
  validator classes, §4.5): SQLi, XSS, IDOR/broken access control, SSRF,
  RCE/command injection, XXE, insecure deserialization, auth/session flaws,
  host privilege escalation.
- **frameworks/** — WordPress, PHP stacks, Django/Flask, Node/Express.
- **protocols/** — SMB, FTP, SSH, general service enumeration.
- **platforms/** — Active Directory chains, container/Docker escape.
- **tooling/** — command-line playbooks for nmap, sqlmap, ffuf, Metasploit.

## Every skill has a Bypass & Evasion section (§6.5.2 — required)

Real targets are defended (WAFs, rate limits, input sanitization, CAPTCHAs). A
protection blocking an attempt is a **sub-problem to route around, not a dead
end** — so every skill carries class-specific bypass/evasion techniques on
equal footing with methodology, techniques, and validation. The stall detector
(§5.3) deliberately treats a bypass attempt as forward progress, not
repetition.

Each skill ends by tying confirmation back to **Gate 1**: no class is a
finding until its deterministic validator (§4.5, §4.7) reproduces it — "no
PoC, no finding."

## Status

The vulnerability skills covering the currently-built validators (SQLi, XSS,
command injection, path traversal, SSRF) plus a representative exemplar for
each other category are authored. The remaining vulnerability classes (IDOR,
XXE, insecure deserialization, auth/session, privesc) and additional
framework/protocol/platform/tooling entries follow the identical template and
are the fast follow-on to complete the full catalog.
