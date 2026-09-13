---
name: active-directory
description: Attacking Active Directory environments. Use when a Windows domain, domain controller, Kerberos (88), LDAP (389/636), or SMB domain membership is found. Covers enumeration, credential-access chains (Kerberoasting, AS-REP, relay), lateral movement, evasion, and Gate 1 confirmation.
metadata:
  category: platforms
  platform: active-directory
  attack_ids: [T1558, T1550, T1075, T1210, T1482]
---

# Active Directory

## Attack surface
Domain controllers (Kerberos 88, LDAP 389/636, SMB 445, RPC), domain users
and computers, SPNs, GPOs, ACLs, trust relationships, and the certificate
services (AD CS). AD chains are common on harder HackTheBox boxes.

## Methodology
1. **Enumerate** (any foothold): users/groups/computers, SPNs, ACLs, GPOs,
   trusts — BloodHound-style graphing to find the shortest path to DA.
2. **Credential access**: AS-REP roast (no-preauth accounts), Kerberoast
   (SPN-bearing accounts), NTLM relay (unsigned SMB/LDAP), password spraying.
3. **Lateral movement**: pass-the-hash/ticket, overpass-the-hash, WinRM/SMB
   exec with obtained creds; escalate along ACL/GPO abuse paths.
4. **Domain dominance**: DCSync, golden/silver tickets, AD CS abuse — only to
   prove the reachable consequence (restraint).

## Techniques
- Kerberoasting → offline crack of the SPN ticket.
- AS-REP roasting for pre-auth-disabled accounts.
- ACL abuse (GenericAll/WriteDACL) for targeted takeover.
- Relay coercion (PetitPotam-style) when signing is off and in scope.

## Bypass & evasion (required)
- **Lockout/spray discipline**: one password per account per policy window;
  read the lockout policy first.
- **Detection**: prefer built-in/LOLBin tooling, avoid noisy default
  ticket options, jitter timing. (Never for malicious detection-evasion —
  only to model a realistic in-scope attacker.)
- A blocked path (signing on, MFA, tiering) is a fresh sub-problem: pivot to a
  different SPN, ACL edge, or trust.

## Validation (Gate 1)
Each step is independently verified (§3.5 verifiable-step chaining): a cracked
SPN hash, a ticket that authenticates, an ACL edge actually exercised — not an
inferred path. Access is proven by an action that succeeds post-escalation and
failed before. No PoC, no finding.
