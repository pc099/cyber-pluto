# Cyber Pluto

Pluto is an autonomous cybersecurity testing harness with Claude as its
reasoning core, forked from [Pi](https://github.com/earendil-works/pi). It
runs recon → validation → exploitation against a target, gated by two hard
safety checkpoints. Phase 1 target is HackTheBox-style CTF boxes; Phase 2 is
authorized bug-bounty programs (HackerOne/Bugcrowd) behind a mandatory human
submission gate.

The full design is `docs/Cyber_Pluto_Architecture_Reference_v2.docx` (the
source of truth); the build history is in `progress/PROGRESS.md`.

## Running it

`cyberpluto` opens an interactive operator shell (run it inside **tmux** so you
can detach, close your laptop, and reattach — the engagement keeps running):

```bash
./cyberpluto 10.129.90.219 "find a foothold and escalate" --tunnel
# scope a bug-bounty program instead:
./cyberpluto --scope-file scope.yaml --program acme \
             --traffic-id "X-Bug-Bounty: your-handle" --rate 1
./cyberpluto --help          # all flags
./cyberpluto <target> --dry-run   # show the resolved config, don't launch
```

It pins **scope** before anything runs (the red-lines gate blocks any out-of-
scope action), loads the full stack (recon, Gate 1 validators, red-lines +
kill switch, vision, MSF-first exploitation, lifecycle caps, the operator
console) plus the runtime skill catalog, and briefs the reasoning core. Then
you type instructions — or drive the engagement directly with the **console**:

| command | what it does |
|---|---|
| `/pluto` | menu of all console actions |
| `/status` | engagement overview (also a live widget above the editor) |
| `/findings` | list findings; drill in for evidence + actions |
| `/nodes` | the investigation tree |
| `/attempts` | recent tool audit (ATT&CK-tagged) |
| `/creds` | recovered credentials |
| `/scope` | in-scope hosts |
| `/approve` | **Gate 2** — human-approve a validated finding for submission |
| `/report` | write a Markdown report for a finding |
| `/resume` | clear an environmental pause and continue |
| `/kill` | engage the kill switch (halt now) |

`!cmd` runs raw bash; `touch state/KILL_SWITCH` halts from any pane.

## Choosing the provider / model

Pluto's reasoning core is any model Pi supports. The launcher defaults to
Anthropic Claude Haiku; switch with `--provider` (and optionally `--model`):

```bash
./cyberpluto <target>                                   # default: anthropic / claude-haiku-4-5
./cyberpluto <target> --provider openai-codex           # ChatGPT subscription (Codex OAuth), gpt-5.5
./cyberpluto <target> --provider openai --model gpt-5.5 # OpenAI API key (metered), pinned model
./cyberpluto <target> --model claude-opus-4-8           # a heavier Anthropic model
```

Leaving `--model` off makes Pi pick that provider's default. Authenticate the
provider **once** before launching (credentials are stored by Pi, in `~/.pi`):

| provider | how to authenticate | billing |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` env, or `pi ... /login` | Claude API (metered) or Claude subscription |
| `openai-codex` | run Pi once, `/login`, sign in with **ChatGPT** | your **ChatGPT** Plus/Pro plan (Codex limits) |
| `openai` | `OPENAI_API_KEY` env | OpenAI API (pay-as-you-go — *not* the ChatGPT plan) |

> A ChatGPT **subscription** and an OpenAI **API key** are different things: the
> subscription bills through `--provider openai-codex` (sign in with ChatGPT); a
> raw `OPENAI_API_KEY` is separate metered billing. Pick `openai-codex` to spend
> the subscription.

> **Codex refuses offensive-exploit work.** OpenAI's ChatGPT/Codex backend
> server-side-flags exploitation content ("flagged for possible cybersecurity
> risk") and stops — it needs their *Trusted Access for Cyber* program
> (`chatgpt.com/cyber`). Until you have that, `openai-codex` is only usable for
> recon/analysis, not the actual exploitation Pluto exists to do. **Anthropic is
> the default** because Claude supports authorized security testing (CTF/HTB).

To make a provider the permanent default, change `PROVIDER=` (and `MODEL=`) at
the top of the `cyberpluto` script.

## The two gates (non-negotiable)

1. **Gate 1** — a finding only reaches `validated` when a deterministic,
   non-LLM validator reproduces it (baseline → attack → compare). The
   reasoning core's confidence is never enough.
2. **Gate 2** — nothing is submitted externally without recorded human
   approval. `/approve` records a `submissions` row naming the approver;
   Pluto never submits to a platform itself — the operator files it.

## Layout

```
cyberpluto                      # the operator launcher (interactive shell)
extensions/src/                 # TypeScript — the Pi extension layer
  tool-log/ recon/ validators/  #   audit · recon→tree→KB · Gate 1 validators
  red-lines/ lifecycle/         #   §10.4 safety gate + kill switch · engagement caps
  vision/ exploit/ delegation/  #   screenshots→vision · MSF-first · sub-agents
  cockpit/                      #   the operator console + Gate 2 + reports
  state/                        #   Layer 2 SQLite schema + typed repositories
services/pluto_services/        # Python — the surrounding services
  kb/ msf_bridge/ oob/          #   seeded KB (Qdrant) · Metasploit · blind-class OAST
runtime-skills/                 # Pluto's runtime doctrine skills (vuln classes, etc.)
lab/                            # intentionally-vulnerable local targets for testing
pi/pi/                          # the Pi fork (git submodule)
```

Run the tests: `cd extensions && npm test` (TypeScript) and
`cd services && .venv/bin/python -m pytest` (Python).

## The split stack

- **TypeScript** (`extensions/`) — the Pi fork and every extension.
- **Python** (`services/`) — KB ingestion/embeddings, the Qdrant client, the
  Metasploit bridge, and the out-of-band interaction server.
- The boundary is deliberate: no agent-loop logic in Python, no KB logic in the
  TypeScript extensions.

## Isolation

Pi has no built-in permission system and inherits the launching user's
permissions. Pluto is intended to run **containerized** — do not assume Pi
sandboxes anything on its own. (The build currently runs directly on a VPS;
containerizing it is the top hardening item.)
