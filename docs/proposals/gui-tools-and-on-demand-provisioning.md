# Proposal: GUI tools (Burp/Wireshark/…) + on-demand provisioning in a headless, sandboxed harness

**Status:** DRAFT for board huddle. Analysis only — nothing built. Raised by the
operator: "how would the CLI use Burp / Wireshark / any GUI tool, and how does
on-demand tool installation work?"

Pluto is headless (runs `--headless` on a VPS) and, under `--sandbox`, runs as a
confined `pluto` uid on a frozen read-only tree with an egress allowlist. Both
questions collide with that model. Two principles resolve them.

## Principle 1 — Use the headless TWIN, never the GUI

Almost every "GUI" security tool has a CLI / daemon / API equivalent that a
headless agent drives natively. The GUI is never the integration surface.

| GUI tool | Headless twin the harness uses |
|---|---|
| **Wireshark** | **`tshark`** (same dissectors, CLI) + `dumpcap`/`tcpdump` for capture. No GUI, no X server. |
| **Burp Suite** | **OWASP ZAP** in daemon mode, or **mitmproxy/mitmdump** — FOSS, API-first, lighter. (Details below.) |
| Nmap "Zenmap" | `nmap` (already core). |
| Metasploit (msfconsole) | `msfrpcd` + the planned MSF bridge (already in the roadmap). |

So the tool strategy is **CLI/daemon-first**. A truly GUI-only tool (rare in
security tooling) is the only case that would need a virtual framebuffer
(`Xvfb`) — noted as a last resort, not a normal path.

### Wireshark concretely
Add `tshark`/`tcpdump` to the `forensics` (and a network domain) manifest.
Capture to a pcap with `dumpcap`/`tcpdump`, analyze with
`tshark -r file.pcap -Y '<display filter>' -T json/fields`. Fully scriptable;
the agent calls it like any bash tool, gated + logged like everything else. No
special work beyond the manifest entry.

### Proxy/DAST tools (Burp/ZAP/mitmproxy) concretely
A CLI agent uses a proxy by: (1) launching it as a **background daemon** bound
to localhost, (2) routing target traffic through it (`HTTP(S)_PROXY` /
proxychains), (3) driving scans and reading findings via its **REST API** (ZAP)
or addon scripts (mitmproxy). The agent talks to the local daemon through a thin
REST extension — the exact pattern the Shodan extension already established.

## Burp specifically — allowed, but not the default

- Modern **Burp Pro** does have a headless mode (`--headless.mode`) with a
  built-in REST API (proxy 8080, REST 8090, localhost) and community drivers
  (burp-cli, burpa, Headless-Burp). But it is Java, heavyweight (4–8 GB RAM vs
  ZAP's 2–4 GB — a real cost on this swapless 3.8 GB box), **licensed**
  (Pro/Enterprise), and PortSwigger's own automation product is **Enterprise**
  (costly); Pro headless "isn't designed for pipeline use."
- **OWASP ZAP** is the FOSS, API-first, lighter, unlicensed equivalent
  (`zap.sh -daemon -port 8080` + full REST API, Docker, SARIF). It is the
  natural default for the proxy/DAST role in a headless harness.
- **Recommendation:** default the proxy/DAST role to **ZAP daemon** (or
  mitmproxy for lightweight scripted interception). Reach for **Burp only via
  Decision 0001's MCP re-open trigger** — Burp's genuine differentiator is
  interactive *live state* (proxy-history/Repeater), which is precisely the
  "interactive live-state + first-party + auditable" case the board already
  conceded (PortSwigger ship a first-party Burp MCP). So Burp, if ever needed,
  arrives as an MCP-bridge case, not a bash tool — consistent with the ratified
  MCP decision. Do not add Burp as a default dependency.

## Principle 2 — "On-demand" means AT LAUNCH, class-driven — not mid-confined-run

The hard tension: under `--sandbox` the tree is frozen read-only, `no_new_privs`
blocks privilege escalation, and the egress allowlist blocks the package repos —
so a genuine **mid-run `apt`/`pip` is architecturally impossible** in confined
mode. That is *why* today's `provision_capability` is deliberately VERIFY-ONLY
(it confirms a domain's pre-vetted toolset is present and surfaces its doctrine
skill; it does not install).

Reconcile on-demand provisioning with the sandbox like this:

1. **Provision at launch, before the privilege drop, driven by the engagement
   class** (operator-declared, or detected in a short recon pre-phase). The
   launcher (root) installs the domain's **pre-vetted manifest packages** with
   package-repo egress briefly open, THEN re-freezes the tree, applies the
   target-scoped egress allowlist, and drops to `pluto`.
2. **Inside the sandbox, `provision_capability(domain)` stays VERIFY-ONLY** —
   exactly its current behavior. The model picks a *domain*, never a package
   (the manifest whitelist is the injection-proof boundary); if the domain's
   tools aren't present, it reports that and the operator re-launches with them.
3. **Heavy daemons (ZAP, msfrpcd) run root-managed on localhost**, started by
   the launcher before the drop — the same pattern as the Gate-1 promotion
   signing daemon. The confined agent drives them through a REST extension; it
   never manages the daemon lifecycle or holds their privileges.
4. **Re-provisioning between runs** (stop, install more from the manifest,
   re-freeze, resume) is the escape hatch when a new class is discovered
   mid-engagement. True mid-confined-run install stays out of scope by design —
   that is a safety property, not a gap.

Non-sandbox / interactive runs can install more freely (root, no freeze), but
the manifest whitelist still governs *what* can be installed.

## What this would add (if the board agrees)

- Manifest entries: `tshark`/`tcpdump` (forensics/network); `zaproxy` +
  `mitmproxy` (web/proxy). Model picks the domain; packages stay whitelisted.
- A launch-time provisioning step in the launcher (root, pre-drop) that installs
  the detected/declared domain's packages, then freezes + drops.
- A ZAP REST extension (Shodan-patterned) + a root-managed ZAP daemon, if/when a
  proxy/DAST capability is wanted. Candidate-only results, gated, logged.
- Burp left to the MCP re-open path; not a dependency.

## Open questions for the board

1. Is launch-time (class-driven) provisioning enough, or is a between-runs
   re-provision flow needed for real engagements? (Harness-architect.)
2. ZAP vs mitmproxy as the default proxy — full DAST scanner, or lightweight
   scriptable interception first? (Cybersecurity + QA on scope creep.)
3. Does a root-managed ZAP daemon add an unacceptable new privileged surface
   (Java, parses attacker traffic) the way the capture-proxy did? (Griller.)
4. What proves a provisioned domain actually works confined — a per-domain
   smoke test at launch? (QA.)
