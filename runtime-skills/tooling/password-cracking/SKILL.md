---
name: password-cracking
description: How to crack a recovered password hash effectively and — just as important — how to know when to STOP cracking and pivot. Use when you have a hash (shadow, htpasswd/$apr1$, service hash) and want the plaintext. Fixes the failure mode where the harness burns effort on tiny wordlists or grinds an uncrackable hash instead of trying rules or moving on.
metadata:
  category: tooling
  tool: john/hashcat/hashid
  pairs_with: linux-privilege-escalation
  attack_ids: [T1110, T1555]
---

# Password Cracking

## 1. Identify the hash BEFORE attacking it

`hashid '<hash>'` (or `hashid -m` for the hashcat mode). Common cases:
- `$apr1$…` → Apache md5crypt (john `--format=md5crypt`, hashcat `-m 1600`).
- `$1$…` md5crypt, `$5$…` sha256crypt, `$6$…` sha512crypt (`-m 1800`), `$2y$…` bcrypt (`-m 3200`).
Picking the wrong mode = guaranteed failure.

## 2. Attack in escalating cost — a bounded bet, not an open-ended grind

1. **rockyou** (provisioned at `/usr/share/wordlists/rockyou.txt`, 14M words):
   `john --wordlist=/usr/share/wordlists/rockyou.txt --format=<fmt> hash.txt`
2. **rockyou + rules** (mutations — the biggest single win over a bare list):
   `john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 --format=<fmt> hash.txt`
   or hashcat: `hashcat -m <mode> -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule`
3. **Target-specific list**: `cewl` the site + theme words, combine with rules.
4. `john --show hash.txt` to read a crack.

## 3. Know when to STOP — cracking is a bet, not a phase

- **No GPU here** — slow hashes ($6$, bcrypt) are effectively uncrackable on CPU
  beyond rockyou+rules. Do NOT grind them for hours.
- **Time-box it:** one rockyou pass + one rockyou+rules pass. If both fail,
  **the password is not the way in** — mark the line dead and PIVOT (kernel/SUID/
  cron privesc, credential in a config/backup, another service). A hash you can't
  crack is a signal to change approach, not to try a 5th wordlist.
- **Use access you already have** first: with RCE you can often read the plaintext
  from a config, history, DB, or backup instead of cracking at all.

## Restraint

Crack only creds you recovered in-scope; never spray a cracked password beyond the
engagement; retain hashes/plaintext minimally as evidence.
