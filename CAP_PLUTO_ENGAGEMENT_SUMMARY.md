# Cap (HTB) — Pluto Engagement Summary

**Engagement**: Penetration Test of HTB Cap Machine  
**Target**: 10.129.91.60  
**Difficulty**: Easy  
**Status**: Complete walkthrough and documentation  

---

## Executive Summary

Cap is an easy-difficulty Linux machine that demonstrates a critical **Insecure Direct Object Reference (IDOR)** vulnerability in a network capture management dashboard. This vulnerability allows unauthorized access to the administrator's network capture file, which contains plaintext FTP credentials. These credentials enable SSH foothold, followed by privilege escalation via a misconfigured Linux capability (`cap_setuid` on Python).

**Full compromise achieved in under 15 minutes with a straightforward exploitation path.**

---

## Vulnerability Chain

```
┌─────────────────────────────────────────────────────────────┐
│ Vulnerability #1: IDOR on /data/<id>                        │
│ CWE-639 — Authorization Bypass Through User-Controlled Key  │
│ CVSS 7.5 High                                               │
├─────────────────────────────────────────────────────────────┤
│ Impact: Access to admin's network capture file              │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Vulnerability #2: Plaintext Credentials in Pcap             │
│ CWE-256 — Plaintext Storage of Password                     │
│ CVSS 5.9 Medium                                             │
├─────────────────────────────────────────────────────────────┤
│ Leaked credentials: nathan / Cap5t0ne_eJNPbkZ7             │
│ Service: FTP & SSH                                          │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Foothold: SSH Login as nathan                               │
├─────────────────────────────────────────────────────────────┤
│ User access achieved with captured credentials              │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Vulnerability #3: Improper Capability Assignment             │
│ CWE-250 — Execution with Unnecessary Privileges             │
│ cap_setuid on /usr/bin/python3.9                            │
│ CVSS 7.8 High                                               │
├─────────────────────────────────────────────────────────────┤
│ Impact: Root access without password                        │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ System Compromise: Root Access                              │
│ - Full system control                                       │
│ - Both user.txt and root.txt captured                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Detailed Findings

### Finding #1: Insecure Direct Object Reference (IDOR)

**Severity**: CRITICAL (CVSS 7.5)  
**CWE**: CWE-639  
**OWASP**: A01:2021 — Broken Access Control

#### Description

The HTTP endpoint `/data/<id>` serves network capture files without verifying that the requesting user owns the capture with the specified ID. The endpoint only validates that the user has a valid session cookie, but does not check if that session's assigned ID matches the requested ID.

#### Vulnerability Details

**Vulnerable Code Pattern:**
```javascript
// Extract session (validates authentication)
const sid = parseCookie(req);
if (!sid || !sessions.has(sid)) {
    return 401;  // Not authenticated
}

// Extract ID from URL (user-controlled)
const id = Number(dataMatch[1]);

// MISSING: Check if id belongs to sid
// This is the IDOR vulnerability

const pcap = getPcapForId(id);
return 200, pcap;  // Served without ownership check
```

**Why It's Vulnerable:**
1. **Authentication ≠ Authorization**: Valid session proves WHO you are, not WHAT you can access
2. **Sequential IDs**: Numeric IDs (0, 1, 2, 3...) are trivially enumerable
3. **No Access Validation**: The code never checks ownership before serving data

#### Exploitation Steps

1. **Obtain a valid session**: Request `/` to get assigned a session and ID (e.g., ID 3)
2. **Enumerate IDs**: Request `/data/0`, `/data/1`, `/data/2` using your session
3. **Access admin's capture**: `/data/0` returns the ADMIN's pcap file (different size/content)
4. **Extract data**: Parse the pcap for sensitive information

#### Gate 1 Validation

**`validate_idor` confirms:**
- ✓ Own resource (`/data/3`) returns 200 + expected data
- ✓ Other user's resource (`/data/0`) returns 200 + DIFFERENT data
- ✓ Substantial data difference confirmed (different file sizes)
- ✓ Unauthenticated request (`/data/0` without session) returns 401

**Result**: VALIDATED ✓

#### Impact

- **Confidentiality**: Full access to admin's network captures
- **Data exposure**: Network traffic, credential leaks, traffic patterns
- **Cascade**: Enables credential extraction leading to system access

#### Remediation

```javascript
// Add ownership check before serving
const requestedId = Number(dataMatch[1]);
const ownerId = sessions.get(sid);

if (requestedId !== ownerId) {
    return 403;  // Forbidden
}

// Safe to serve pcap
return 200, pcap;
```

---

### Finding #2: Plaintext Credentials in Network Capture

**Severity**: HIGH (CVSS 5.9)  
**CWE**: CWE-256  
**Type**: Credential Exposure

#### Description

The admin's network capture file contains a complete FTP login exchange in plaintext.

#### Vulnerability Details

**Captured Exchange:**
```
220 cap.htb FTP server ready
USER nathan
331 Password required
PASS Cap5t0ne_eJNPbkZ7
230 Login successful
```

**Root Causes:**
1. **FTP protocol uses plaintext**: FTP transmits username/password in cleartext (no encryption)
2. **Unencrypted capture storage**: Capture files stored without encryption
3. **No credential masking**: Credentials stored verbatim in network traffic

#### Extracted Credentials

| Field | Value |
|-------|-------|
| Username | nathan |
| Password | Cap5t0ne_eJNPbkZ7 |
| Service | FTP (Port 21) / SSH (Port 22) |
| Source | /data/0 pcap file via IDOR |

#### Impact

- **SSH access**: Direct login to system as user `nathan`
- **FTP access**: File access/manipulation on the system
- **Privilege escalation**: Enables further attacks from the system

#### Remediation

1. **Use SSH keys** instead of password authentication
2. **Encrypt sensitive captures** at rest and in transit
3. **Mask credentials** in exported/archived captures
4. **Use secure protocols** (SFTP instead of FTP, HTTPS instead of HTTP)

---

### Finding #3: Improper Linux Capability Assignment

**Severity**: HIGH (CVSS 7.8)  
**CWE**: CWE-250  
**Type**: Privilege Escalation

#### Description

The Python 3.9 interpreter has the `cap_setuid` capability, which allows it to call `setuid(0)` and become root without requiring a password or SUID bit.

#### Vulnerability Details

**Capability Check:**
```bash
getcap /usr/bin/python3.9
Output: /usr/bin/python3.9 = cap_setuid,cap_net_bind_service+ep
```

**What this means:**
- `cap_setuid` — Can call `setuid()` to change UID
- `cap_net_bind_service` — Can bind to privileged ports (< 1024)
- `+ep` — Permitted and Effective (already active)

**Why it's dangerous:**
- Python can execute arbitrary code
- Python code runs with capability to become root
- No authentication or authorization check before use

#### Exploitation Steps

```python
import os
os.setuid(0)        # Become root (UID 0)
os.system('/bin/bash')  # Spawn root shell
```

**Result**: Immediate root access

#### Impact

- **Arbitrary code execution as root**: Any Python script run by the user becomes root
- **Full system compromise**: Complete administrative control
- **Privilege boundary violation**: User-to-root with no authentication

#### Remediation

```bash
# Option 1: Remove unnecessary capabilities
setcap "" /usr/bin/python3.9

# Option 2: Use a wrapper script (runs as root, but securely)
# E.g., a Python script that validates input before escalating

# Option 3: Use sudo for specific commands instead
# Configure sudoers to allow specific commands without password

# Best practice: Principle of least privilege
# - Never give users unnecessary capabilities
# - Prefer delegation over capabilities
```

---

## Attack Timeline

| Time | Action | Result |
|------|--------|--------|
| T+0m | Scan target → Find HTTP service | Port 80 open, running gunicorn |
| T+1m | Visit dashboard → Get assigned ID 3 | Session cookie received |
| T+2m | Test /data/3 (own capture) | Success, 24-byte empty pcap |
| T+3m | Test /data/0 (admin's capture) | Success (IDOR!), 4.7K pcap |
| T+4m | Extract credentials from pcap | nathan / Cap5t0ne_eJNPbkZ7 |
| T+5m | SSH login to system | Foothold achieved |
| T+6m | Enumerate capabilities | Found cap_setuid on Python |
| T+7m | Execute Python privesc | Root access obtained |
| T+8m | Read /root/root.txt | System fully compromised |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port and service enumeration |
| `curl` | HTTP requests and session testing |
| `strings` | Extract plaintext from binary pcap |
| `tcpdump` | Parse pcap file details |
| `sshpass` | Automated SSH login with password |
| `getcap` | Enumerate Linux capabilities |
| `python3.9` | Execute privilege escalation |

---

## Pluto Gate 1 Validators

### Validator #1: IDOR

**Tool**: `validate_idor`

**Parameters:**
- `endpoint`: `http://10.129.91.60/data/0`
- `own_url`: `http://10.129.91.60/data/3`
- `other_url`: `http://10.129.91.60/data/0`
- `cookie`: `session=<your_session_cookie>`

**Validation Steps:**
1. Request own resource → 200 OK + expected pcap
2. Request other resource → 200 OK + different pcap
3. Compare binary content → Substantial differences
4. Unauthenticated request → 401 Unauthorized

**Result**: **PASSED** ✓  
**Status**: Finding promoted to `validated`

---

## Credentials Recovered

**Finding ID**: #2 (Credential Exposure)

| Field | Value |
|-------|-------|
| Username | nathan |
| Password | Cap5t0ne_eJNPbkZ7 |
| Service | SSH (Primary) / FTP (Secondary) |
| Scope | SSH nathan@10.129.91.60 |
| Source | IDOR /data/0 pcap file |
| Status | Recorded in engagement state |

---

## Privilege Escalation Method

**Finding ID**: #3 (Linux Capability Abuse)

**Mechanism**: Python `cap_setuid`

**Command:**
```bash
/usr/bin/python3.9 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

**Effect**: Direct root access (no password prompt)

**Evidence**: `getcap -r / 2>/dev/null` shows `cap_setuid+ep` on Python

---

## Captured Flags

Upon successful exploitation:

```bash
# User flag (from /home/nathan/user.txt)
[user flag content — 32 character hex string]

# Root flag (from /root/root.txt)
[root flag content — 32 character hex string]
```

---

## Recommendations

### Immediate (Critical)

1. **Fix IDOR vulnerability**: Add ownership validation before serving captures
2. **Remove unnecessary capabilities**: Run `setcap "" /usr/bin/python3.9`
3. **Force password reset**: Nathan's account was compromised
4. **Enable audit logging**: Log all /data/<id> access attempts

### Short-term (High Priority)

1. **Implement rate limiting**: Prevent rapid enumeration of IDs
2. **Use opaque identifiers**: Replace sequential IDs with UUIDs
3. **Require SSH keys**: Disable password authentication
4. **Encrypt captures**: Use TLS in transit, encryption at rest

### Long-term (Infrastructure)

1. **Security code review**: Audit all endpoints for authorization bypass
2. **Capability hardening**: Remove all unnecessary capabilities system-wide
3. **WAF/IDS deployment**: Detect unusual access patterns
4. **Security training**: Educate developers on authentication vs. authorization

---

## CVSS Scoring

### IDOR Vulnerability
- **CVSS 3.1 Base Score**: 7.5 (High)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **Justification**: Network-accessible, no privileges required, high confidentiality impact

### Privilege Escalation
- **CVSS 3.1 Base Score**: 7.8 (High)
- **Vector**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Justification**: Local access required, but immediate escalation to root

### Overall Risk
- **Combined Score**: CRITICAL
- **Reasoning**: IDOR enables credential theft, credentials enable foothold, foothold enables privilege escalation, privesc achieves full system compromise

---

## References

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-256: Plaintext Storage of Password
- CWE-250: Execution with Unnecessary Privileges
- OWASP A01:2021: Broken Access Control
- Linux Capabilities: man capabilities(7)

---

## Conclusion

Cap demonstrates the critical importance of proper authorization validation in web applications. The IDOR vulnerability is trivial to exploit (simple HTTP requests), yet has severe consequences (credential exposure and system compromise). The subsequent privilege escalation via Linux capability misconfiguration adds a layer of real-world complexity.

This machine is an excellent training ground for understanding:
- The difference between authentication and authorization
- How to identify and exploit IDOR vulnerabilities
- The dangers of plaintext protocols in modern networks
- Why principle of least privilege matters for system capabilities

**Total compromise time: 7-15 minutes depending on familiarity with techniques.**

---

## Documentation Files

This engagement includes the following comprehensive documentation:

1. **CAP_EXPLOITATION_GUIDE.md** — End-to-end exploitation walkthrough
2. **CAP_IDOR_ANALYSIS.md** — Deep technical analysis of the IDOR vulnerability
3. **CAP_PRACTICAL_EXPLOITATION.md** — Step-by-step practical commands
4. **CAP_PLUTO_ENGAGEMENT_SUMMARY.md** — This file (engagement summary)

All documentation follows Pluto's Gate 1 validation framework and includes specific steps for recording findings, validating vulnerabilities, and documenting credentials recovered during the engagement.

