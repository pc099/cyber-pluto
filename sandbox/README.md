# Sandbox — agent confinement (board-ratified v0)

This closes the two escalated security items: the agent **cannot modify the
harness's own trusted files** (so an injected write can't disable the red-lines
gate), and the scope control is an **authoritative network-egress allowlist**,
not command-text parsing.

Decided by a 3-agent review board (harness-architect, cybersecurity, griller)
in a huddle — **unanimously ratified**. The board rejected a container for v0
(Docker fights this box's `iptables-nft` backend + libvirt's `virbr0` rules,
OOMs a swapless 3.8 GB box under chromium/KVM, and can't IP-pin the CDN
provider) in favor of the mechanism validated on this box.

## The model

The agent runs as a **dedicated unprivileged uid `pluto`**, and:

1. **Read-only harness tree** — the whole runtime (repo, `extensions/dist`,
   `node_modules`, the `pi/` bundle, `.pi/`, `runtime-skills/`, `node`) is
   root-owned and world-read-only, so `pluto` can execute + read but not write.
   An injected `echo > extensions/src/red-lines/check.ts` gets `EROFS`/EACCES.
   Only `engagements/<label>/` and `/tmp` are writable.
2. **`no_new_privs`** (via `setpriv`) — a setuid-root tool (e.g. `ping`) cannot
   elevate, so its packets are attributed to `pluto` and caught by the egress
   filter. This closes the setuid egress-attribution bypass. It also blocks the
   LPE-to-root path (`pkexec`/`sudo` can't elevate).
3. **bubblewrap** — read-only bind of the fs, writable bind of only the
   engagement workspace + `/tmp`, minimal `/dev`+`/proc`.
4. **Authoritative egress** — an `nftables` `meta skuid pluto` **default-DROP**
   OUTPUT allowlist, applied by the ROOT launcher *before* the agent starts,
   from **operator scope only**: allow the in-scope target hosts, the LLM
   provider endpoint(s), loopback, and DNS to one resolver; DROP everything
   else. It lives in root's ruleset, so `pluto` (no `CAP_NET_ADMIN`) can't flush
   it, and it never touches root/operator/VPN traffic. Verified on the box:
   `pluto` reached an allowed IP, was DROPPED to a disallowed one, root
   unaffected. Every child tool and sub-agent inherits the filter automatically.
5. **Credentials** — the root launcher **env-injects** the provider API key into
   the dropped-uid child; it lives only in that process's `/proc/<pid>/environ`
   (0400, root+pluto), never on disk. Root's `~/.pi` stays `700`. Use a
   rotatable/scoped key.
6. **Kill switch** — stays root-owned `state/KILL_SWITCH`; the operator writes
   it, `pluto` read-only-polls it, and it is now **un-deletable by the agent**.
7. **`provision_capability` is verify-only** — tools are pre-baked; the agent
   has no writable system dirs and no package-repo egress.

## One-time setup

The harness must live **outside `/root`** (which is `0700`, so `pluto` can't
even traverse into it). `setup.sh` deploys it to a traversable path and freezes
it:

```bash
cd /root/cyber-pluto/extensions && npm run build      # build as root FIRST (frozen tree can't build)
sudo /root/cyber-pluto/sandbox/setup.sh /opt/cyber-pluto
```

## Run a confined engagement

```bash
cd /opt/cyber-pluto
sudo ./cyberpluto <target> --sandbox --headless        # applies egress from scope, drops to pluto
# halt:  sudo touch /opt/cyber-pluto/state/KILL_SWITCH
```

`--sandbox` (root) applies `sandbox/egress.sh` from the resolved scope +
provider, then runs the agent via `sandbox/run-sandboxed.sh`. Tearing down the
run removes the egress table.

## Scripts

- `setup.sh` — create `pluto`, deploy to a traversable path, freeze the tree,
  and generate the Gate-1 promotion signing keypair (see below).
- `egress.sh apply "<scope hosts/CIDRs>" [provider_host…]` / `teardown` / `show`.
- `run-sandboxed.sh <engagement_dir> -- <cmd…>` — the privilege-drop + bwrap wrapper.

## Gate-1 promotion signing (Item 0)

The state DB is `pluto`-writable, so a hijacked agent could forge a validated
finding with a raw `UPDATE findings SET status='validated'`. To make that inert,
every legitimate `candidate→validated` promotion is signed with an ed25519 key
**held by root, outside pluto's reach**, and consumers treat an unsigned/invalid
`validated` row as tampered.

- `setup.sh` generates the keypair: the **private** key at
  `/etc/cyber-pluto/promotion_ed25519.key` (root-only `0400`), the **public** key
  at `…/promotion_ed25519.pub` (`0444`).
- Under `--sandbox` the launcher starts a **root signing daemon**
  (`promotion-sign-daemon`) before dropping to `pluto`. It holds the private key
  and listens on a unix socket in the pluto-writable engagement dir; the confined
  agent reaches it via `promotion-sign-client`. A socket — **not sudo** — is used
  because the sandbox runs under `no_new_privs`, which disables setuid (hence
  sudo). The daemon re-derives the claim from the DB and re-verifies the gate as
  root before signing.
- **Verified live on the box:** under `no_new_privs`, `pluto` gets *Permission
  denied* on the private key but *can* obtain a valid signature through the
  socket; the daemon refuses a claim for a missing/failing validation.
- **Honest residual:** the `validations` table is also pluto-writable, so a
  hijacked agent can forge a `passed` validation row and then obtain a legitimate
  signature for it. This closes the direct status-flip, not the
  forged-validation-row path — that needs privileged re-validation (Item-0
  follow-on). Consumer enforcement (readers demoting unsigned/invalid `validated`
  findings) is the remaining increment.

## Residual risks (on record, accepted for v0)

- **Kernel LPE** — a kernel exploit escapes any uid/namespace boundary (a
  container wouldn't stop a kernel escape either). Deferred defense-in-depth:
  seccomp/AppArmor + a mount namespace hiding host secrets (Milestone-2).
- **Provider channel** — the agent must reach the LLM API and can encode data
  into prompts (and read its own key). Bounded by a rotatable key, volume
  logging, and the Gate-2 human submission gate.
- **DNS tunnel** — the one allowed resolver is a low-bandwidth covert channel;
  it logs every query and targets need no DNS.

## Deferred to Milestone-2 (reproducibility + defense-in-depth)

A reproducible container image (nspawn, not Docker on this box), a mount
namespace for read-confinement of host secrets, seccomp/AppArmor, and DNS-set
population of the provider allowlist by the controlled resolver.
