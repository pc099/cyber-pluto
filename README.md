# Cyber Pluto

Pluto is an autonomous cybersecurity testing harness with Claude as its
reasoning core, forked from [Pi](https://github.com/earendil-works/pi).
Phase 1 target is HackTheBox-style CTF challenges; Phase 2 is authorized
bug-bounty programs (HackerOne/Bugcrowd) behind a mandatory human
submission gate.

The full design lives in `docs/Cyber_Pluto_Architecture_Reference_v2.docx`
(the source of truth) and the session-by-session build sequence in
`CLAUDE_CODE_BUILD_PLAN.md`. `CLAUDE.md` and `.claude/skills/` carry the
build doctrine for Claude Code sessions working this repo.

This README describes the repo layout as of **Session 0 (scaffolding
only)** — the split toolchain exists and each side builds a hello-world,
but no agent-loop, state-schema, gate, or extension logic has landed yet.

## Layout

```
cyber-pluto/
├── CLAUDE.md                    # Project context for Claude Code (always in context)
├── CLAUDE_CODE_BUILD_PLAN.md    # Session-by-session build sequence
├── docs/                        # Architecture Reference + Kali GUI VPS Setup Guide
├── progress/
│   ├── PROGRESS.md              # Resumable ledger — read this first every session
│   └── sessions/                # Longer per-session notes, as needed
├── .claude/skills/               # Build doctrine skills (pluto-build, typescript-patterns,
│                                 #   python-patterns, cybersecurity-modules)
├── pi/pi/                       # The Pi fork (earendil-works/pi), cloned but untouched —
│                                 #   Session 1 integrates it. Untracked by this repo's git
│                                 #   until then (see .gitignore).
├── extensions/                  # TypeScript — Pluto's custom Pi extension layer:
│                                 #   vision pipeline, agent-delegation, the red-lines
│                                 #   pre-execution hook, tool-call logging. Builds with
│                                 #   `npm install && npm run hello` (proves the toolchain).
└── services/                    # Python — KB ingestion, embeddings, the vector-store
                                  #   (Qdrant) client, and the Metasploit MCP bridge.
                                  #   Venv + `requirements.txt`; run with
                                  #   `python3 -m venv .venv && source .venv/bin/activate
                                  #   && pip install -r requirements.txt
                                  #   && python -m pluto_services.hello`.
```

## The split stack

- **TypeScript** (`extensions/`, and eventually `pi/`) — the Pi fork and
  every custom extension: vision pipeline, agent-delegation, the
  red-lines hook, the tool-call path.
- **Python** (`services/`) — KB ingestion, embeddings, the vector-store
  client, and the Metasploit MCP bridge.
- The boundary is deliberate: no agent-loop logic in Python, no KB logic
  in the TypeScript extensions.

## The two gates (non-negotiable — see `CLAUDE.md` for the full list)

1. **Gate 1** — only a deterministic, non-LLM validator promotes a
   finding from `candidate` to `validated`.
2. **Gate 2** — nothing is submitted externally without recorded human
   approval.

## Isolation

Pi has no built-in permission system and inherits the launching user's
permissions. Pluto is run containerized — never assume Pi sandboxes
anything on its own.

## Provisioning

This harness runs on a hardened Kali-toolset VPS; see
`docs/Cyber_Pluto_Kali_GUI_Setup_Guide.docx` for the provisioning model
(droplet → Kali package repo → XFCE + VNC over an SSH tunnel for optional
visual access). Pluto's own operation is headless and does not depend on
the GUI once it's running unattended.
