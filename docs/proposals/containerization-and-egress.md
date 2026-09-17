# Proposal: Containerization + network-egress control (for board review)

Status: DRAFT for the 3-agent review board. This closes the two items the board
escalated from the last review: (C2) the agent must not be able to write the
harness's own trusted files, and the scope control must be an authoritative
**network-egress allowlist**, not text-parsing of commands.

## Goals (what "done" means)

1. **Harness tree is read-only to the agent.** An injected `echo … >
   extensions/src/red-lines/check.ts` or an edit to `.pi/settings.json` must
   FAIL, so the red-lines gate cannot be neutered for the next launch/sub-agent.
2. **Authoritative egress allowlist.** The agent process can reach ONLY: the
   in-scope target host(s), the chosen LLM provider API, and (if runtime
   provisioning stays) a small tooling allowlist. All other egress is DROPped —
   so an injected exfil to `evil.com` fails at the network layer regardless of
   how the command is written (this is what text-parsing can't guarantee).
3. **Minimal disruption** to the current run model (`cyberpluto` → Pi + the
   `.pi` profile), and it must still reach the target via the host VPN/NAT.

## Concrete environment facts (researched, not assumed)

- Droplet: Debian 13, **root**, 3.8 GB RAM / 2 vCPU, `/dev/kvm` present.
- Containers/sandbox: **not installed but installable** — `docker.io` 26.1.5,
  `podman` 5.4.2, `bubblewrap` 0.12, `nftables` 1.1.3. **Present already:**
  `systemd-nspawn` (systemd 257), `unshare` (util-linux). **User namespaces
  ENABLED** (`unprivileged_userns_clone=1`, `max_user_namespaces=15519`) → rootless
  sandboxes are viable. `iptables` (nf_tables backend) present.
- Networking to targets is host-side: `tun0` (HTB VPN) and `virbr0` 192.168.122.0/24
  (the local VulnHub KVM NAT). A sandbox must reach the in-scope target through
  these while egress-restricting everything else.
- Filesystem needs:
  - READ-ONLY to the agent: `extensions/`, `.pi/`, `runtime-skills/`, `pi/`, `.claude/`, `docs/`.
  - READ-WRITE: the per-engagement workspace only — `engagements/<label>/{state,logs,evidence,reports}` and `/tmp`.
  - TENSION: `provision_capability` does `apt-get`/`pip install` at RUN TIME →
    needs writable system dirs + package-repo egress, which fights read-only +
    a tight allowlist.

## Proposed approach (v0 — to be grilled)

**A. Container runtime: Docker (`docker.io`).** Reproducible image, first-class
read-only mounts, and the cleanest egress-firewall story. Rootless
Docker/Podman considered; rootful Docker with a non-root *in-container* user is
the v0 for simplicity, revisit rootless.

**B. Pre-baked image `pluto-runtime`.** All pentest tooling baked in at build
time (nmap, chromium, telnet, expect, pwntools, gdb, ROPgadget, sqlmap, node,
the Pi bundle build). This **resolves the provisioning tension**:
`provision_capability` becomes verify-only (tools already present), so no
runtime `apt`/`pip` and no package-repo egress hole. New tools ⇒ rebuild the
image, not a live install.

**C. Filesystem.** Bind-mount the repo read-only; bind-mount only
`engagements/<label>/` read-write; agent runs as UID != 0 inside. The `-a`
auto-trust is now safe: the trusted tree is physically read-only.

**D. Egress allowlist (the authoritative scope control).** The container runs in
its own netns. An `nftables` egress policy: default DROP; ALLOW only
(1) the in-scope target host(s) resolved from `scope.yaml`/`PLUTO_SCOPE_HOSTS`
(dynamic, written per engagement), (2) the LLM provider API IP/host, (3) DNS to
a controlled resolver. The `extractHosts` red-lines rule stays as cheap
defense-in-depth in front of this.

**E. Target routing.** The container reaches `tun0`/`virbr0` targets via the
host. Options (the hard tradeoff — see below): host networking (simple, weak
isolation) vs a routed bridge + firewall (isolated, more setup).

## The hard tradeoffs / open questions FOR THE BOARD

1. **Docker vs bubblewrap vs systemd-nspawn.** Docker = best egress/image story,
   heaviest, another daemon on a 3.8 GB box. bubblewrap = rootless + lightweight,
   already-viable userns, but weaker network-policy tooling. nspawn = present,
   good isolation, VPN routing fiddlier. Which is the right weight for a
   single-operator box?
2. **`--network host` vs isolated netns.** Host networking trivially reaches the
   VPN/NAT target but **defeats the egress allowlist** (the whole point). An
   isolated netns needs the target route plumbed in AND the firewall — more
   work but it's the only way egress control is real. Is the routing complexity
   worth it, or is there a simpler enforcement point (a forced proxy)?
3. **Forced-proxy alternative to a netns firewall.** Instead of L3 firewalling,
   force ALL agent HTTP(S) through a proxy that only permits in-scope hosts +
   provider. Simpler for HTTP exfil, but doesn't stop raw sockets / `nc` / DNS
   exfil. Is L3 (nftables) strictly required, or proxy + a minimal L3 backstop?
4. **The LLM provider egress is itself an exfil channel.** The agent must reach
   the provider API; a hijacked agent could encode data into prompts. Accept, or
   mitigate?
5. **Pre-bake vs keep runtime provisioning.** Pre-baking kills the writable-
   system + repo-egress hole but makes the image heavier and tool updates a
   rebuild. Keep a *narrow* runtime-install escape hatch (writable overlay +
   pypi/debian allowlist) or forbid it?
6. **Where does `cyberpluto` sit** — on the host launching the container, or
   inside? The launcher builds scope/briefing/env; the container needs those +
   the per-engagement egress rules generated from scope.

## Non-goals (v0)

Multi-tenant isolation, seccomp/AppArmor hardening beyond read-only + egress,
and full log/evidence per-engagement isolation (tracked separately).
