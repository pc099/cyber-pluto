# Engagement phases & model routing

Pluto runs one engagement as a sequence of **phases**. The reasoning model is
chosen **per phase**, so the offensive "attack surface" work can run on a
different model than the orchestration — without changing any gate. The two
gates, the red-lines check, scope enforcement, and the audit log are identical
in every phase and every sub-agent (they are loaded structurally in
`delegation/spawn.ts`, so a different model on the attack phase is still bounded
by §10.4).

## The phases

| # | Phase | What happens | Runs on |
|---|-------|--------------|---------|
| 1 | **Recon / enumerate** | port/service scan, content discovery, grow the tree | main model (orchestrator) |
| 2 | **Hypothesize / validate (Gate 1)** | reason about candidates; deterministic **non-LLM** validators promote `candidate → validated` | main model + the validators (no model judgment inside the gate) |
| 3 | **Exploitation — the attack surface** | write the payload / exploit / custom delivery for a **validated** finding | **attack model** (`--attack-provider` / `--attack-model`) |
| 4 | **Post-exploitation / privesc** | use the foothold, escalate, capture proof | attack model (offensive), main model orchestrates |
| 5 | **Report (Gate 2)** | assemble the finding report; **human** approval before any external submission | main model + operator |

## How the switch works

A phase boundary is a **delegation** (§6.4). When Pluto hands the exploitation
sub-task to the `exploitation` specialist (`delegate_handoff` /
`consult_specialist`), that sub-agent is spawned on the **attack model**; recon
and analysis specialists, and the orchestrator, stay on the **main model**.
Routing lives in one place — `subAgentTarget()` in `delegation/spawn.ts`:

- main provider/model  ← `PLUTO_SUBAGENT_PROVIDER` / `PLUTO_SUBAGENT_MODEL`
- exploitation phase   ← `PLUTO_ATTACK_PROVIDER` / `PLUTO_ATTACK_MODEL`
  (falls back to the main model when unset, so nothing diverges until you
  configure an attack model).

## Why route the attack phase separately

Hosted assistants increasingly **refuse offensive-exploit content** at the
provider (OpenAI Codex: "flagged for possible cybersecurity risk"). Routing only
the exploitation phase to an **open-weight model** — free-tier hosted (Groq,
Cerebras, OpenRouter) or self-hosted (llama.cpp / vLLM, OpenAI-compatible) —
gets the exploit written without paying metered API cost, while the rest of the
engagement uses whatever orchestration model you prefer.

## Examples

```bash
# whole engagement on one free-tier open model (no metered API cost):
./cyberpluto <target> --provider groq --model llama-3.3-70b-versatile

# split: orchestrate on one model, run the attack phase on another:
./cyberpluto <target> --provider groq  --model llama-3.3-70b-versatile \
                      --attack-provider cerebras --attack-model qwen-3-coder-480b

# attack phase on a self-hosted local model (OpenAI-compatible endpoint):
./cyberpluto <target> --provider groq --attack-provider llama.cpp --attack-model qwen2.5-coder
```

Set the provider's key in the environment first (e.g. `GROQ_API_KEY`,
`CEREBRAS_API_KEY`, `OPENROUTER_API_KEY`); a self-hosted endpoint needs no key.
