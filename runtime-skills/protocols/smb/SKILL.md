---
name: smb
description: Testing SMB/NetBIOS services (139/445). Use when SMB is fingerprinted on a host. Covers null sessions, share and user enumeration, signing checks, common SMB vulnerability classes, and follows the §5.1 order (cheap checks before CVE exploits).
metadata:
  category: protocols
  service: smb
  ports: [139, 445]
  attack_ids: [T1135, T1110, T1210]
---

# SMB / NetBIOS

## Attack surface
File shares, IPC$, named pipes, RID space, and the SMB protocol stack itself.
Many HackTheBox boxes turn on a misconfigured share, not a web bug.

## Methodology (§5.1 order — cheap first)
1. **Check first**: null/anonymous session on IPC$, default/weak creds,
   credential reuse from elsewhere.
2. **Enumerate**: share listing, RID-cycling user enum, SMB signing status,
   readable/writable shares, spidered file contents.
3. **CVE path**: version-specific RCEs (EternalBlue-class MS17-010, SMBGhost)
   only after the cheap checks — and via a Metasploit module when one fits
   (§2.3.2).

## Techniques
- **Null session**: `smbclient -N -L //host`, `enum4linux-ng`, `rpcclient -U ""`.
- **Share access**: list, download, and search shares for creds/config.
- **User enum**: RID cycling; feed found users into credential testing.
- **Signing**: unsigned SMB enables relay (NTLM relay) if in scope.

## Bypass & evasion (required)
- **Auth lockouts**: spray slowly (one attempt per account per window) rather
  than brute one account; reuse creds harvested elsewhere first.
- **SMB dialect/signing**: downgrade or select dialects when a check refuses;
  try both 139 and 445.
- **Filtered access**: pivot via a readable share or named pipe when direct
  admin is blocked. A refusal is a sub-problem, not a stop.

## Validation (Gate 1)
Access is proven by content actually retrieved (a share's files, a user list),
not a bare connection. An RCE CVE is a candidate until reproduced (a working
module session or deterministic PoC). A version banner alone is only a
`candidate`. No PoC, no finding.
