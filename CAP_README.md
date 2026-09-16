# Cap (HTB) — Complete Engagement Documentation

This directory contains comprehensive documentation for exploiting the **Cap** machine from HackTheBox, including detailed walkthrough guides, technical vulnerability analysis, and Pluto gate validation procedures.

---

## Quick Start

**For impatient attackers**: Start with `CAP_PRACTICAL_EXPLOITATION.md` — it has all the commands you need to own the box in ~13 minutes.

**For learning**: Start with `CAP_EXPLOITATION_GUIDE.md` — it explains what's happening and why at each step.

**For pentesting reports**: Use `CAP_PLUTO_ENGAGEMENT_SUMMARY.md` — it has CVSS scores, CWE references, and remediation advice.

**For deep technical understanding**: Read `CAP_IDOR_ANALYSIS.md` — it dissects the vulnerability mechanics.

---

## Documentation Guide

### 1. CAP_EXPLOITATION_GUIDE.md (Recommended First Read)

**Length**: ~10 minutes  
**Level**: Beginner to Intermediate  
**Content**:
- Phased exploitation walkthrough (Recon → IDOR → Foothold → Privesc)
- Pluto Gate 1 validation procedures
- Clear step-by-step instructions
- Finding summary with CVSS scores
- Credential recovery process
- Attack chain diagram

**Best for**: Understanding the complete attack path and learning how each vulnerability connects.

### 2. CAP_PRACTICAL_EXPLOITATION.md (Copy-Paste Commands)

**Length**: ~15 minutes (actual exploitation)  
**Level**: Practitioner  
**Content**:
- Concrete bash commands with expected output
- Enumeration techniques (nmap, curl, strings)
- IDOR exploitation with file size verification
- Credential extraction from pcap files
- SSH login and privilege escalation
- Automated exploitation script
- Troubleshooting common issues

**Best for**: Hands-on exploitation when you want to practice the techniques.

### 3. CAP_IDOR_ANALYSIS.md (Technical Deep Dive)

**Length**: ~20 minutes  
**Level**: Intermediate to Advanced  
**Content**:
- Detailed vulnerability mechanics
- Code-level vulnerability analysis
- Why authentication ≠ authorization
- Sequential ID enumeration strategies
- Pluto's IDOR validator mechanics
- Impact analysis (confidentiality, availability, integrity)
- Detection signatures (network and application level)
- Real-world HTB differences

**Best for**: Security professionals writing reports, developers learning secure coding, teams building validators.

### 4. CAP_PLUTO_ENGAGEMENT_SUMMARY.md (Formal Report)

**Length**: ~15 minutes  
**Level**: Professional/Executive  
**Content**:
- Executive summary of the engagement
- Three detailed findings with CWE/CVSS
- Complete attack timeline
- Gate 1 validator specifications
- Credentials recovered
- Recommendations (immediate/short-term/long-term)
- CVSS scoring breakdown
- Tools used

**Best for**: Management presentations, security reports, compliance documentation.

### 5. app.mjs (Source Code — The Lab)

**Location**: `/root/cyber-pluto/lab/cap-clone/app.mjs`  
**Type**: Node.js HTTP server  
**Content**:
- Intentionally vulnerable Cap-shaped application
- IDOR vulnerability on `/data/<id>` endpoint
- Session-based user assignment
- Embedded libpcap file builder (creates FTP credentials in the binary)

**Best for**: Local testing, understanding the vulnerable code, practicing against a safe target.

---

## Vulnerability Summary

### Vulnerability Chain

```
IDOR (/data/<id>)
    ↓ (access admin's capture)
Plaintext FTP Credentials (nathan / password)
    ↓ (SSH login)
Foothold as user nathan
    ↓ (enumerate system)
Linux Capability cap_setuid on Python
    ↓ (os.setuid(0))
ROOT ACCESS ✓
```

### Three Critical Findings

| Finding | CWE | CVSS | Impact |
|---------|-----|------|--------|
| IDOR on /data/<id> | 639 | 7.5 | Access admin's pcap |
| Plaintext credentials in pcap | 256 | 5.9 | Credential exposure |
| cap_setuid on Python | 250 | 7.8 | Privilege escalation |

---

## Attack Timeline

| Time | Phase | Key Action |
|------|-------|-----------|
| 0-2 min | Recon | Identify HTTP service, visit dashboard |
| 2-5 min | IDOR | Test /data/0, enumerate IDs |
| 5-8 min | Extraction | Parse pcap, extract credentials |
| 8-10 min | Foothold | SSH login as nathan |
| 10-13 min | Privesc | Discover cap_setuid, escalate to root |

---

## Pluto Integration

### Gate 1 Validation

All findings are validated through Pluto's deterministic Gate 1 validators:

**Finding #1: IDOR**
```
Tool: validate_idor
Parameters:
  - own_url: /data/3 (your assigned capture)
  - other_url: /data/0 (admin's capture)
  - cookie: session=<your_session>
Result: VALIDATED ✓
```

**Finding #2: Credential Exposure**
```
Type: Data extraction from validated finding #1
Credentials: nathan / Cap5t0ne_eJNPbkZ7
Storage: Engagement state via record_credential
```

**Finding #3: Privilege Escalation**
```
Type: System enumeration leading to capability abuse
Mechanism: cap_setuid + Python os.setuid(0)
Proof: getcap output + root shell
```

### Recording Findings

```bash
# Step 1: Record IDOR candidate
/findings record-candidate

# Step 2: Validate with Gate 1
/findings validate-idor

# Step 3: Record credential
/creds record

# Step 4: Generate report
/report generate-finding
```

---

## Files in This Documentation Set

```
/root/cyber-pluto/
├── CAP_README.md                           ← You are here
├── CAP_EXPLOITATION_GUIDE.md               ← Start here (overview)
├── CAP_PRACTICAL_EXPLOITATION.md          ← Commands to run
├── CAP_IDOR_ANALYSIS.md                   ← Technical details
├── CAP_PLUTO_ENGAGEMENT_SUMMARY.md        ← Formal report
│
└── lab/cap-clone/
    └── app.mjs                            ← Vulnerable Node.js app
```

---

## Key Concepts

### Authentication vs. Authorization

- **Authentication**: Proving WHO you are (session cookie)
- **Authorization**: Proving WHAT you can access (ownership check)

Cap's vulnerability: The code checks authentication but skips authorization.

### Sequential ID Enumeration

IDs 0, 1, 2, 3, 4, 5... are trivially enumerable.
- ID 0 = Admin's capture (largest, contains credentials)
- ID 1-2 = System captures (empty)
- ID 3+ = User captures (empty)

### Linux Capabilities

Instead of granting root access via SUID bit, modern systems use capabilities.
`cap_setuid` on Python = "This Python process can call setuid()"

This is dangerous when users run their own Python code.

---

## Exploitation Prerequisites

- Basic Linux command-line knowledge
- Understanding of HTTP requests and cookies
- Familiarity with SSH
- Knowledge of packet capture (pcap) files
- Comfort with bash scripting

**No special tools required** — everything uses standard utilities (curl, ssh, strings, tcpdump).

---

## Success Criteria

You've successfully exploited Cap if you can:

1. **Extract the admin's pcap** via IDOR (without being granted it)
2. **Parse FTP credentials** from the pcap file
3. **SSH into the box** using those credentials
4. **Escalate to root** using the cap_setuid vulnerability
5. **Read both user.txt and root.txt** flags

---

## Common Mistakes to Avoid

❌ **Mistake**: Assuming a session cookie grants access to all resources  
✓ **Fix**: Always check that the resource belongs to the authenticated user

❌ **Mistake**: Using sequential IDs without testing lower numbers  
✓ **Fix**: Enumerate systematically (0, 1, 2, 3...) to find high-value resources

❌ **Mistake**: Trying to exploit cap_setuid before getting shell access  
✓ **Fix**: Get foothold first via SSH, then escalate from there

❌ **Mistake**: Not verifying the pcap file before extracting data  
✓ **Fix**: Check file type and size first

---

## Related Vulnerabilities

- **OWASP A01:2021** — Broken Access Control (the umbrella category)
- **CWE-639** — Authorization Bypass Through User-Controlled Key
- **CWE-256** — Plaintext Storage of Password
- **CWE-250** — Execution with Unnecessary Privileges

---

## Testing Against Real Cap

These instructions work against:
- The HTB Cap machine (if you have access)
- Any similar vulnerable application
- The local lab clone at /root/cyber-pluto/lab/cap-clone/app.mjs

The main differences from the lab to real Cap:
- Real Cap uses FTP/SSH with actual system credentials (not synthetic)
- Real Cap's captures may contain more complex network traffic
- Real Cap might require more thorough recon to identify the capture service

---

## Questions?

### "Is this legal?"

Exploitation instructions are provided for:
- Educational purposes on CTF platforms (HackTheBox)
- Authorized penetration testing engagements
- Understanding security concepts

Always ensure you have written authorization before testing systems you don't own.

### "What if the target doesn't respond?"

Check:
1. Is your session still valid?
2. Is ID 0 the correct admin ID?
3. Is the target actually vulnerable?

### "Can I use this against a real application?"

Yes — these same techniques apply to any IDOR vulnerability:
1. Identify resource IDs (numeric, UUID, etc.)
2. Attempt to access resources outside your scope
3. If successful, you've found an IDOR
4. Follow the remediation advice to fix it

---

## Document Navigation

- [Exploitation Guide](CAP_EXPLOITATION_GUIDE.md) — start here for overview
- [Practical Commands](CAP_PRACTICAL_EXPLOITATION.md) — actual commands to run
- [IDOR Technical Analysis](CAP_IDOR_ANALYSIS.md) — deep dive
- [Pluto Summary Report](CAP_PLUTO_ENGAGEMENT_SUMMARY.md) — formal writeup

---

**Last Updated**: 2026-09-14  
**Prepared by**: Pluto Automated Security Harness  
**Status**: Complete end-to-end engagement documentation  
