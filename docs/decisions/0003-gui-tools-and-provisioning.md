# Decision 0003 — GUI tools + on-demand provisioning (unanimous board)

Decided by the 4-agent review board (harness-architect, cybersecurity, griller,
QA) with a huddle on `docs/proposals/gui-tools-and-on-demand-provisioning.md`.
**Ratified.** The board substantially revised the proposal; the draft's
"launch-time install as the normal path", "recon-detected class", and
"root-managed ZAP daemon" were all rejected or downgraded.

## Decision

1. **Headless-twin principle: ADOPTED.** A headless agent never uses a GUI; it
   uses the CLI/daemon/API twin. Wireshark → `tshark` (file analysis is a pure
   bash tool). CLI-first for everything.

2. **Sequencing — this is DEFERRED behind higher-value work.** None of it
   unblocks the one thing that has never happened: a full end-to-end HackTheBox
   run. Priority order (griller, unopposed): (1) first HTB run; (2) the ratified
   Gate-1 slices (evidence-hash, OOB collector) — prerequisites to trusting that
   run's findings; (3) cheap CLI manifest adds; (4) any proxy/DAST. Items 3–4
   are post-first-run by the project's own "defer until real findings" doctrine.

3. **On-demand install = BAKE-TIME by default; launch-time is the EXCEPTION.**
   - The frozen/reproducible image (tools baked at `setup.sh` time, **version-
     and hash-pinned**) stays the default. This preserves the frozen-image
     invariant the sandbox depends on.
   - Launch-time root install (before the privilege drop) is allowed only as an
     exception, and only with: **operator-DECLARED** engagement class (NOT
     auto-detected — a recon pre-phase that classifies from attacker-influenced
     banners is a new unconfined injection surface; unanimous reject), **version
     + hash pins** (`pip --require-hashes`; apt signed repos only), egress opened
     to a **specific pinned repo host** (not "package repos" broadly), and a
     **mandatory verified re-freeze** (re-assert root-owned + `ro` over the newly
     written `/usr` + site-packages, fail-closed if the tree isn't read-only
     before drop).
   - **Mid-confined-run install is impossible by design** and stays so.
     `provision_capability` remains VERIFY-ONLY inside the sandbox.

4. **"Between-runs re-provision" is a manual relaunch, not a confined feature —
   but it is worth building** (needed for Phase-2 bug-bounty pivots). MVP
   (architect): checkpoint → SIGTERM agent → egress teardown → root re-provisions
   the accumulated domain list → verified re-freeze → re-apply egress → resume
   the **same engagement label/state**. Human in the loop; no new confined
   install path.

5. **No root-managed DAST daemon now. mitmproxy-first if any proxy; ZAP
   deferred; CLIs preferred.**
   - A 2–4 GB ZAP JVM co-resident with chromium/node/KVM on the swapless 3.8 GB
     box is an OOM risk (griller, architect, QA). Single-binary CLIs
     (`nuclei`/`ffuf`/`sqlmap`) need no daemon, are attributed to `pluto`, and are
     caught by the egress filter — prefer them.
   - If a scriptable proxy is wanted, **mitmproxy** (Python addons) before ZAP.
   - **Any proxy/DAST MUST NOT run as root** (cybersecurity — a proxy holds no
     secret and parses attacker traffic; root egress is unrestricted, so a
     root-run proxy silently defeats the scope allowlist). It runs as `pluto` or
     a dedicated filtered uid whose egress is in the same default-DROP allowlist.
   - Active scanning is aggressive: default **passive/spider only**, active scan
     a separate explicitly-approved capability, scope-enforced at the proxy
     config (mirroring egress) and rate-limited; results **candidate-only**,
     logged, ATT&CK-tagged (the Shodan pattern).

6. **Burp: OUT for v0 (unanimous).** A headless autonomous harness does not
   consume Burp's only differentiator (interactive live-state/Repeater). It is
   Java, heavy, licensed. It may return ONLY via Decision 0001's MCP re-open
   trigger if a genuine interactive-live-state need appears — never as a default
   dependency. "PortSwigger ship an MCP" is availability, not a need.

7. **Live pcap CAPTURE (not analysis) needs a small root helper.** `CAP_NET_RAW`
   / setuid are dead under `no_new_privs`, so live capture is a root-managed
   helper dumping to a pluto-readable pcap; `tshark -r <file>` stays a pure bash
   tool.

## Testing gates (QA — mandatory before anything here ships)

- **Per-domain confined smoke test:** after provisioning, run the domain's REAL
  work AS `pluto` through `run-sandboxed.sh` against a committed fixture (e.g.
  `tshark -r fixtures/smoke.pcap -T fields -e ip.src` exits 0 + emits the known
  IP) — not just the `command -v` verify string.
- **Re-freeze NEGATIVE test = new sandbox control #12:** as `pluto` post-drop,
  `apt-get install` / `pip install` MUST fail (EROFS / egress-DROP / no sudo) and
  the package be absent; paired with a positive test that an in-scope host is
  still reachable (proves the allowlist swapped, not emptied).
- **Any DAST ship gate (non-negotiable):** the **out-of-scope negative
  interception test** — drive a scan at an out-of-scope host, prove ZERO requests
  reach it (scope gate consulted BEFORE dispatch, not result-filtered) and
  results are candidate-only. Plus a gated LIVE run for real daemon startup,
  memory ceiling/OOM, port clash, and spider-honors-allowlist.
- Regression: the extension suite (96/96) and sandbox controls (11/11 → 12/12)
  must stay green.

## The survivable near-term residue

Post-first-HTB-run, when a real need is shown: add `nuclei`/`ffuf`/`tcpdump`
(and confirm `tshark`) as plain CLI manifest entries, version/hash-pinned,
provisioned at launch by the operator-declared class, each with its confined
smoke test. **No daemon, no Burp, no auto-detect, no ZAP** unless a later need
re-opens them. ~a handful of manifest lines gated behind evidence they're needed.

## Status

Ratified; **not built and intentionally deferred** behind the first end-to-end
HTB run and the Gate-1 slices. This record is the plan for when it is picked up.
