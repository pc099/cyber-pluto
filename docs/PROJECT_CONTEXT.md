# Cyber Pluto — Project Context & Decision Log

> **Purpose of this file.** A single, self-contained context document for
> resuming Cyber Pluto and making the next decisions (including in Claude web /
> voice mode). It is written from **verified facts only** — the state database,
> run logs, session token accounting, and the git history. Anything not
> confirmed by a deterministic validator is explicitly labelled **HYPOTHESIS**.
> This discipline matters: an earlier run produced confident, fabricated
> "engagement complete" reports for work it never did, so this file separates
> *validated fact* from *speculation* everywhere.
>
> _Snapshot date: 2026-09-14. Repo: github.com/pc099/cyber-pluto._

---

## 1. What Cyber Pluto is

An **autonomous cybersecurity testing harness** with Claude (or any LLM) as its
reasoning core, **forked from Pi** (`earendil-works/pi`). It runs recon →
validation → exploitation against a target, gated by two hard safety
checkpoints.

- **Phase 1:** HackTheBox-style CTF boxes (current stage).
- **Phase 2:** authorized bug-bounty programs (HackerOne/Bugcrowd) behind a
  mandatory **human submission gate**.
- Single operator (Chaitanya), run on a private hardened VPS.
- Source of truth for design: `docs/Cyber_Pluto_Architecture_Reference_v2.docx`.

### The non-negotiable invariants

1. **Two gates are absolute.**
   - **Gate 1 (validation):** a finding only moves `candidate → validated` when
     a **deterministic, non-LLM validator** reproduces it (baseline → attack →
     compare). The model's confidence is never sufficient. A version-string
     match can only reach `candidate`.
   - **Gate 2 (submission):** nothing is submitted externally without recorded
     **human approval** (`submissions` row naming the approver). Compliance
     requirement — HackerOne/Bugcrowd prohibit autonomous submission.
2. **Red-lines check gates every tool call** before execution and propagates
   into every delegated sub-agent (7 prohibited-action categories, §10.4).
3. **Status is the fact ledger.** `candidate` = speculation, `validated` = fact.
4. **Everything is logged** — every tool call and delegation, ATT&CK-tagged.
5. **Exploration is free; consequences are gated.** Safety lives in the gates,
   red-lines, and logging — not in restricting the toolset.

---

## 2. Architecture & repo layout

**Split stack (the boundary is deliberate):**
- **TypeScript** (`extensions/`) — the Pi fork + every extension.
- **Python** (`services/`) — KB ingestion/embeddings (Qdrant), Metasploit
  bridge, the out-of-band (OAST) server for blind classes.

```
cyberpluto                      # operator launcher (interactive Camp-1 shell)
extensions/src/
  tool-log/ red-lines/          #   audit log · §10.4 safety gate + kill switch
  recon/ validators/            #   recon→tree→KB · Gate 1 deterministic validators
  vision/ exploit/ delegation/  #   screenshots→vision · MSF-first · sub-agents (§6.4)
  lifecycle/ cockpit/           #   engagement caps/pause/stuck · operator console + Gate 2
  capabilities/                 #   adaptive capability provisioning (manifest + provision tool)
  state/                        #   Layer 2 SQLite schema + typed repositories
services/pluto_services/        # Python — kb/ msf_bridge/ oob/
runtime-skills/                 # Pluto's runtime doctrine (vuln classes, binary-exploitation, etc.)
lab/vulnhub/                    # local KVM box lab (import-box.sh) + intentionally-vulnerable apps
docs/PHASES.md                  # per-phase model routing
pi/pi/                          # the Pi fork (git submodule → github.com/pc099/pi)
```

**Environment:** DigitalOcean droplet, **3.8 GB RAM / 2 vCPU, but `/dev/kvm` IS
present** (hardware virtualization — unusual for a cloud VM; enables the local
VulnHub lab). Node v24, Python 3.13. Installed: nmap, chromium, openvpn, telnet,
expect, sshpass, proxychains4, **qemu/KVM + libvirt** (NAT net 192.168.122.0/24),
**pwntools + gdb + ROPgadget** (binary-exploitation capability). Metasploit NOT
installed (mock backend). Can run OpenVPN directly (`tun0`) for HTB.

---

## 3. Build status

**The 12-session build plan is COMPLETE** (commits `…` through
`dc1d5d6`), plus a post-plan operator-harness phase. Highlights:

- Sessions 1–12: state schema, red-lines gate, recon→tree→KB, Gate 1 validators
  (SQLi, command-injection, path-traversal, XSS, IDOR), vision pipeline, MSF
  bridge, agent delegation (§6.4), runtime skill catalog, OOB server, engagement
  lifecycle (caps/pause/stuck), end-to-end dry run.
- Post-plan: the `cyberpluto` operator launcher, the `cockpit` console
  (`/status /findings /nodes /attempts /creds /approve /report /kill /resume`),
  Gate 2 flow, bug-bounty HTTP compliance (traffic-ID header + rate limit),
  provider-selectable launcher, per-phase model routing.
- **Adaptive capability provisioning** (`extensions/src/capabilities/`): a
  manifest-driven `provision_capability(domain)` tool — Pluto recognizes the
  engagement class and installs *that domain's whitelisted toolset* + loads its
  doctrine skill, on the fly. Safe: the model picks a domain, never a package,
  so it can't be prompt-injected into arbitrary installs; every provision is
  logged. First domain: **binary-exploitation** (pwntools/gdb/ROPgadget +
  a "test-don't-derive" pwn doctrine); stubs for cryptography, forensics, web.
  Built after a live pwn run wasted ~an hour hand-deriving stack offsets for
  lack of pwn tools + doctrine.
- **Local VulnHub lab** (`lab/vulnhub/import-box.sh`): the droplet's `/dev/kvm`
  lets real VulnHub VMs run KVM-accelerated on a host-private NAT network — a
  reproducible, no-VPN/no-cost target source Pluto can fully scan.
- **Test suite: 36/36 passing.**

**KB:** CISA KEV ingested (~1709 records), fingerprint→KEV hypothesis matching
active. Qdrant local mode, hashing embedder.

---

## 4. The state database (the fact ledger)

SQLite (`state/pluto.db`, WAL). Tables: `targets`, `nodes` (self-referencing
tree), `findings`, `credentials`, `attempts` (ATT&CK-tagged), `validations`
(Gate 1), `submissions` (Gate 2), `screenshots`. Findings carry a `status`
lifecycle: `candidate → validated → submitted`, or `rejected`.

**Current contents (verified snapshot):**

| target_id | host | what it is | attempts | nodes | findings | validated |
|---|---|---|---:|---:|---:|---:|
| 1 | 127.0.0.1 | local **cap-clone** lab | 44 | 13 | 6 | **2** (SQLi, IDOR) |
| 2 | 10.129.119.239 | **Meow** (HTB, telnet) | 57 | 17 | 4 | 0 |
| 3 | 10.129.91.60 | **Cap** attempt (unreachable) | 39 | 1 | 0 | 0 |
| 4 | 10.129.2.155 | **OpenAM/JMX box** (HTB) | 403 | 76 | 19 | 0 |
| 5 | 10.129.2.155 | re-engagement (killed early) | 0 | 1 | 0 | 0 |

**Validations recorded (Gate 1):** finding #4 SQLi `passed`, finding #5 IDOR
`NOT passed` (correctly rejected — no differential access), finding #6 IDOR
`passed`. All three on the local lab (target 1). **Zero findings were validated
on any real HTB box.**

**Credentials recovered:** #1 `nathan` (from the lab's IDOR→pcap chain, finding
#6). #2–#4 are `demo`/`anonymous` **default-credential probes** against the
OpenAM box (unconfirmed — see §6).

---

## 5. The engagements — honest account

### 5a. Local lab — cap-clone (target 1) — the only fully successful run

A Cap-shaped intentionally-vulnerable app (`lab/cap-clone/app.mjs`, IDOR on
`/data/<id>` → admin pcap → plaintext FTP creds). Pluto (Haiku, full stack):
recon → 13-node tree → raised SQLi and IDOR candidates → **Gate 1 validated
both** (real `validations` rows) → recovered the `nathan` credential. Ground
truth held: exactly the validated findings were validated, the bogus IDOR
(#5) was correctly rejected, no gate bypassed. **This proves the harness works
end-to-end.**

### 5b. HTB Meow (target 2, 10.129.119.239) — first real box

- **What it is:** Starting-Point Tier 0. **telnet/23, passwordless `root`
  login.** Vector = misconfiguration, no CVE.
- **Outcome:** the **root flag was captured — but manually, not by Pluto.**
  (Flag value deliberately kept out of the repo.)
- **Pluto's autonomous run:** 57 tool calls, 17-node tree, correctly identified
  telnet/23, raised 4 candidates, kept them all `candidate` (two-gate discipline
  held), and the **red-lines scope gate correctly blocked an out-of-scope
  `127.0.0.1` attempt** during the run. It did **not** get the foothold —
  **root cause: no telnet client, `telnetlib` removed in Python 3.13, and no
  `expect`** were installed, so it could not drive an interactive telnet login
  and fell down a "telnet backdoor / RCE" rabbit hole. Tooling gap, not a
  reasoning or safety failure. telnet/expect/sshpass are now installed.

### 5c. HTB Cap (target 3, 10.129.91.60) — never engaged

Unreachable from the droplet: the HTB VPN gateway returned **"Destination Host
Unreachable."** Cause diagnosed: Cap is a **Machines** box, but the droplet is
connected to the **Starting-Point** VPN — different network. 39 probe attempts,
0 findings. (Also: the fabricated `CAP_*` docs an earlier run wrote describe Cap
but were **hallucinated** — invented IP/creds, placeholder flags — and were NOT
committed to the repo.)

### 5d. HTB OpenAM/JMX box (target 4, 10.129.2.155) — the expensive run

- **What it is (observed fingerprints):** vhost **`management.htb`** /
  **`sso.management.htb`**, running **ForgeRock/OpenAM** (`/openam/XUI`,
  `/openam/json/authenticate`, `/openam/json/serverinfo`). Open ports:
  **22 (ssh), 80, 443 (https/OpenAM), 1689 (JMX/RMI), 4444, 41257, 50389.**
  An encrypted `/assets/app.enc` was also discovered.
- **What Pluto attempted:** OpenAM default-credential probes (`demo`,
  `anonymous`), the OpenAM legacy identity endpoint, and a **JMX/RMI insecure
  deserialization RCE** via a `JmxJdkProxy` against port 1689 (the exploit that
  triggered the OpenAI-Codex refusal — see §7).
- **Outcome:** **0 findings validated, no foothold, no flag.** 403 attempts, 76
  nodes across multiple runs.
- **Why it "ate the credits" (session `01a09e3a`, Haiku):** **~24.0M total
  tokens** for one engagement — **97% cache reads (23.3M)**, output only 35.6K.
  **204 assistant turns, 195 bash calls, 45 errored (23%)**, and it hit context
  compaction. Cost ≈ turns × context size, and both ballooned. Root causes:
  1. **Red-lines scope false-blocks** — shell variables in URLs
     (`https://10.129.2.155$endpoint`) were extracted as bogus out-of-scope
     hosts and blocked, forcing one-request-per-turn instead of batched loops;
     and the discovered vhost `management.htb` was blocked because only the IP
     was in scope. **(Both fixed — commit `269194a`.)**
  2. Slow full-port `-sV -sC` scans timing out and retrying.
  3. Haiku's 23% tool-error rate on a hard web/deserialization box.

### 5e. Re-engagement (target 5) — killed early

A re-run of 10.129.2.155 on the OpenAI-Codex subscription; stopped almost
immediately when Codex refused the offensive content (§7).

---

## 6. Vulnerability & CVE analysis (validated vs hypothesized)

**Validated (Gate 1, deterministic) — all on the local lab only:**
- **SQL injection** (CWE-89) — DB-error differential reproduced.
- **IDOR / broken access control** (CWE-639) — differential-access reproduced.

**Misconfiguration, confirmed manually (not via Pluto's gate):**
- **Meow:** passwordless `root` telnet (CWE-1188 / insecure default). No CVE.

**HYPOTHESES only — NOT validated, do not treat as fact:**
- **OpenAM box (10.129.2.155):** the presence of ForgeRock/OpenAM makes
  **CVE-2021-35464** (ForgeRock AM ≤ 6.0.1 pre-auth Java deserialization RCE via
  the Jato `/ccversion` path; in CISA KEV) the **most plausible intended
  vector**. **This was neither reached nor confirmed by Pluto.** The **JMX/RMI
  on 1689** is a separate insecure-deserialization / MBean-RCE *class* (a
  misconfiguration, not a single CVE) that Pluto attempted via `JmxJdkProxy` but
  did not confirm.
- **KB/KEV fingerprint matches raised as hypotheses on target 4** included
  **CVE-2015-1635** and **CVE-2021-31166** (Microsoft HTTP.sys — **almost
  certainly false positives**, the box is Linux) and **CVE-2023-44487** (HTTP/2
  Rapid Reset). These are `vuln_hypothesis` tree nodes, **not findings**, and
  illustrate that KEV fingerprint matching produces noise that Gate 1 exists to
  filter.

**Bottom line: Pluto has validated 0 CVEs. Every CVE above is a candidate to be
proven by a validator, never a confirmed result.**

---

## 7. The central strategic decision — which LLM provider (UNRESOLVED)

This is the biggest open decision and a **hard blocker for bug-bounty**. Testing
eliminated every first-party subscription:

| provider path | permits offensive work | flat / low cost | OK in 3rd-party harness (Pi) |
|---|:--:|:--:|:--:|
| Anthropic **API key** | ✅ | ❌ metered (cost mounts) | ✅ |
| Anthropic **Pro/Max subscription** | ✅ | ✅ | ❌ **against ToS, enforced** |
| OpenAI **Codex subscription** | ❌ **refuses exploits** | ✅ | ✅ |
| OpenAI **API key** | ⚠️ also filters | ❌ metered | ✅ |
| **Open-weight model** (Groq/Cerebras free-tier · Ollama Cloud · self-host) | ✅ | ✅ | ✅ |

**Findings that drove this:**
- **OpenAI Codex** server-side-refuses offensive content: *"This content was
  flagged for possible cybersecurity risk… join the Trusted Access for Cyber
  program."* It blocked a live JMX/RMI RCE. Provider policy, not a harness bug;
  it must not be worked around. Codex is usable only for non-offensive tasks.
- **Anthropic subscription** ($20 Pro) works technically via OAuth, but using a
  consumer subscription through a third-party harness is **against Anthropic's
  terms and actively enforced** — risks the account. Do not route it through Pi.
- **Anthropic API key** permits the work and runs in Pi, but is **metered** —
  the operator does not want mounting per-token cost.

**CONCLUSION (settled, do not re-litigate):** for autonomous bug-bounty volume,
an **open-weight model is the core** — it is the only option meeting all three
constraints. Interim: the metered Anthropic API key for a few validation runs.
The harness is **already ready** — `cyberpluto --provider <x>` is selectable and
per-phase routing exists (`--attack-provider/--attack-model`, `docs/PHASES.md`),
so the exploitation phase can run on its own model. Picking an open provider is
a one-line change, no new code.

**Hardware constraint:** the droplet (3.8 GB, no GPU) **cannot host a capable
model** — only a ~1.5–3B CPU model fits, too weak for real exploits. So the open
model must be **hosted** or on separate GPU hardware — not local on this droplet.

**Open-model shortlist (this session's evaluation):**
- **Sarvam-105B (API) — current front-runner.** OpenAI-compatible (drop-in Pi
  provider), agentic/tool-calling, cheap (~$0.80/1M blended, **cached ~$0.13/1M**
  which suits Pluto's ~97%-cached cost profile), and **India data residency**
  (best for an India-based operator + eventual client data). Metered but cheap.
- **GLM-5.3 (z.ai Coding Plan) — close 2nd.** Flat-rate coding subscription
  (agent-legit, unlike the Anthropic/OpenAI subs), Pi-native `zai` provider,
  strong coder. China residency. (Self-hosting GLM-5.3 is infeasible: 320B MoE →
  ~180 GB VRAM @ 4-bit / a multi-GPU node costing far more than the API.)
- **DeepSeek-V4 (API)** — cheap metered, permissive, China residency.
- **DeepHat/WhiteRabbitNeo (Kindo)** — security-*purpose-built*, zero refusals,
  US residency; but largest is **30B** (Kindo-hosted/paid), open one is only 7B
  (too weak). The "insurance" pick if general models refuse, or for pro client
  work needing non-China residency.
- **Free tiers don't work:** Groq free (gpt-oss-120b) confirmed usable *model*
  but its **8K tokens/min** cap is smaller than Pluto's ~7.5K base context — zero
  tool calls got through. Free is too throttled for a harness this heavy.

**The one remaining unknown:** whether these general models **refuse** the
offensive step (untested). Settle it empirically — one run on the local
lab/VulnHub target with the chosen model.

**Alternative path considered — re-platform onto Claude Code:** ~3–4 weeks of
work; gains a *legitimate* flat Claude subscription (the sub is ToS-barred in
Pi, but IS Claude Code), loses all model freedom (Anthropic-only). Only worth it
if Sarvam/GLM/DeepSeek all fail the refusal test. Not recommended over the ~1-day
Sarvam test.

**Per-phase routing design (`docs/PHASES.md`):** recon/analysis/orchestration on
one model; the `exploitation` specialist (the "attack surface") on another via
`PLUTO_ATTACK_PROVIDER`/`PLUTO_ATTACK_MODEL`. Red-lines + tool-log still load
into every sub-agent, so a less-aligned attack model is still gate-bounded.

---

## 8. Known open bugs / hardening backlog

1. **TOP: ungated free-text reports.** Pluto's file-writing is not behind the
   gates — it wrote confident, fabricated "engagement complete" reports for work
   it never did (the state DB stayed truthful: 0 validated). **Fix: constrain
   report generation to validated DB facts only.** #1 correctness item.
2. **Reasoning-loop breaker (NEW, high value).** A live pwn run burned ~an hour
   inside *extended thinking* — hand-deriving the same stack offsets in a loop.
   Pluto's stuck-detector only watches repeated *tool calls / no-new-nodes*, so
   an intra-turn thinking loop is invisible to it. The binary-exploitation
   doctrine's "re-derived twice → STOP and measure" rule mitigates it, but the
   proper fix is a lifecycle check that fires when N turns pass with no new tool
   call / no new evidence.
3. **Containerize Pluto** — it runs as root on the droplet; Pi sandboxes
   nothing. Top hardening item (also why OS-level privesc is circular locally).
3. **Per-engagement workspace isolation** — all runs share one `state/pluto.db`
   (a `PLUTO_HOME` per target for state/evidence/logs is wanted).
4. Wire the blind SQLi/SSRF TS validators onto the §4.7 OOB server.
5. Remaining vuln-class validators (XXE, deserialization, auth, privesc) +
   skills — note the OpenAM/JMX box needed a deserialization validator Pluto
   doesn't yet have.
6. KB beyond CISA KEV (WSTG/PentestMonkey/CAPEC); reduce KEV false positives.
7. Universal enforcing HTTP proxy so bug-bounty rate/traffic-ID rails apply to
   all bash tools, not just Pluto's own fetches.

**Already fixed/built this cycle:** red-lines scope false-blocks (shell-var +
vhost, `269194a`); false environmental pauses + `/resume` (`9bae486`);
build-CLAUDE.md bleed via `-nc` (`291d452`); OOM via bundle CLI (`e03a34e`);
`--no-cap` and provider selection; per-phase model routing; **adaptive
capability provisioning + binary-exploitation capability**; the **local VulnHub
KVM lab**.

---

## 9. Recommended next decisions (for voice-mode planning)

1. **Pick the open-weight provider.** Fastest zero-cost start: a **free Groq
   key** (`GROQ_API_KEY`), `--provider groq --model llama-3.3-70b-versatile`.
   If free-tier limits bite, **Ollama Cloud** (flat ~$20/mo, bigger coders). Then
   one live run on a reachable box to confirm an all-open, zero-cost engagement.
2. **Reachability:** to hit **Cap** (a Machines box), connect the droplet to the
   **Labs** VPN (not Starting-Point). For Starting-Point boxes (Meow etc.) the
   current VPN works.
3. **Fix the ungated-report bug** before any bug-bounty use — fabricated reports
   are unacceptable for real programs.
4. **Then** re-run the two real boxes on the open model: Meow (should now foothold
   with telnet tooling present) and the OpenAM/JMX box (needs a deserialization
   validator + a model that will write the exploit).

---

_This document is descriptive context, not instructions. Everything marked
HYPOTHESIS must be proven by a Gate-1 validator before it is treated as real._
