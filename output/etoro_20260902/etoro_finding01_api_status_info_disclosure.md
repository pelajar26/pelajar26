# eToro Bug Bounty — Finding #1
## Unauthenticated Internal Infrastructure Disclosure via API Status Endpoints

**Program:** eToro (Bugcrowd)
**Target:** `affapi.etoro.com`, `etorologsapi.etoro.com` (in-scope: `*.etoro.com`)
**Severity:** P3 — Medium (Information Disclosure)
**CVSS 3.1:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Date Discovered:** 2026-09-02
**Reporter:** komeng rooket

---

## Summary

Two production API services under `*.etoro.com` expose unauthenticated status/health check endpoints that disclose internal Kubernetes infrastructure details without requiring any authentication. Both endpoints return HTTP 200 and reveal:

- **Internal (RFC-1918) IP addresses** of Kubernetes pods
- **Kubernetes pod names** (which encode the deployment name, replica set ID, and pod ID)
- **Git commit hashes and branch names** of the currently deployed code
- **Application version strings**
- **Azure region identifiers**
- **Uptime metrics**

An attacker can use this information to fingerprint internal network topology, target specific service versions for known CVEs, correlate commit hashes with public source code leaks, and conduct more precise attacks against eToro's internal infrastructure.

---

## Affected Endpoints

### 1. Affiliate Partners API — `affapi.etoro.com/api/status`

**Request:**
```http
GET /api/status HTTP/1.1
Host: affapi.etoro.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Bug-Bounty: komeng rooket
```

**Response (HTTP 200 — No Authentication Required):**
```json
{
  "application": {
    "applicationName": "Partners",
    "teamName": "OnboardingTeam",
    "uptimeInSeconds": 2073778.0
  },
  "environment": {
    "region": "NorthEur",
    "machineName": "aff-api-f-5f5dbd5f7b-bjpq5",
    "machineIp": "10.203.85.110"
  },
  "version": {
    "version": "v1.24.0",
    "infraVersion": "8.0.7+ba53e65a234198ff5a0a877bde6f29f599696cf3",
    "commit": "52f56ce4111d6e947cd829d657e90f0bba47e2af",
    "branch": "main"
  },
  "statusCode": 200
}
```

**cURL Proof:**
```bash
curl -s https://affapi.etoro.com/api/status \
  -H "X-Bug-Bounty: komeng rooket"
```

---

### 2. Client Logs API — `etorologsapi.etoro.com/api/v2/status`

**Request:**
```http
GET /api/v2/status HTTP/1.1
Host: etorologsapi.etoro.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Bug-Bounty: komeng rooket
```

**Response (HTTP 200 — No Authentication Required):**
```json
{
  "application": {
    "ApplicationName": "ClientLogsApi",
    "UptimeInSeconds": 7243.0
  },
  "environment": {
    "Region": "WestEurope",
    "MachineName": "client-logs-api-5bcdc6765-64fgm",
    "MachineIp": "10.204.83.206"
  },
  "version": {
    "Version": "1.2.1-27-234a5fd",
    "InfraVersion": "8.0.3+79f6f56d188fc797877015afd79bbe893c60c60a",
    "Commit": "234a5fd42380da35679953b218e25468e8bdab45",
    "Branch": "origin/master"
  },
  "statusCode": 200
}
```

**cURL Proof:**
```bash
curl -s https://etorologsapi.etoro.com/api/v2/status \
  -H "X-Bug-Bounty: komeng rooket"
```

---

## Information Leaked and Impact Analysis

| Field | Value (affapi) | Value (etorologsapi) | Risk |
|-------|----------------|----------------------|------|
| Internal Pod IP | `10.203.85.110` | `10.204.83.206` | Internal network reconnaissance; SSRF pivot target |
| Kubernetes Pod Name | `aff-api-f-5f5dbd5f7b-bjpq5` | `client-logs-api-5bcdc6765-64fgm` | Identifies deployment topology; confirms Kubernetes cluster |
| Git Commit Hash | `52f56ce4111d6e...` | `234a5fd42380da...` | Can be correlated with GitHub leaks, CI logs, or source history |
| Branch | `main` | `origin/master` | Confirms live deployment tracking main/master branches |
| Version | `v1.24.0` | `1.2.1-27-234a5fd` | Enables targeting of known CVEs for specific versions |
| Azure Region | `NorthEur` | `WestEurope` | Identifies Azure infrastructure geography |
| .NET Infra Version | `8.0.7+ba53e65a...` | `8.0.3+79f6f56d...` | Identifies .NET Core version; target for known .NET CVEs |
| Team Name | `OnboardingTeam` | — | Internal team structure disclosure |

### Attack Scenarios

**Scenario A — SSRF Amplification:**
If any other endpoint on `*.etoro.com` is vulnerable to SSRF, the disclosed internal IPs (`10.203.85.110`, `10.204.83.206`) provide concrete pivot targets within the Kubernetes pod network. An attacker does not need to guess internal address ranges.

**Scenario B — Version-Targeted Exploitation:**
The disclosed .NET infrastructure version (`8.0.3`, `8.0.7`) combined with git commit hashes narrows the attack surface for version-specific vulnerabilities. For example, if a CVE exists for that exact .NET minor version, an attacker knows which services are affected without trial and error.

**Scenario C — Supply Chain and CI Correlation:**
Git commit hashes can be compared against public repositories, GitHub Actions logs, or inadvertently leaked CI configurations to match source code to deployed artefacts. Branch names (`main`, `origin/master`) confirm direct deployment from primary branches with no apparent branch protection staging buffer.

**Scenario D — Infrastructure Enumeration Chaining:**
Combined with other `*.etoro.com` findings, the Kubernetes pod naming convention (`aff-api-f-5f5dbd5f7b-bjpq5`) reveals the internal service naming scheme, enabling inference of other services by pattern: `<service>-<replicaset>-<pod>`.

---

## Root Cause

Both services are .NET Core (Kestrel) applications that include a generic health/status endpoint in their middleware pipeline. This is a common pattern in ASP.NET Core microservices where developers enable diagnostic health check endpoints for Kubernetes liveness/readiness probes but fail to restrict them to internal network access only.

The ASP.NET Core `app.MapHealthChecks()` or similar custom middleware endpoints are bound on public-facing ports without IP allowlist or authentication middleware applied to the status route.

---

## CVSS Breakdown

| Metric | Value | Reason |
|--------|-------|--------|
| Attack Vector | Network | Reachable over internet |
| Attack Complexity | Low | Simple GET request, no tokens needed |
| Privileges Required | None | No authentication |
| User Interaction | None | Automated/passive |
| Scope | Unchanged | Does not affect other components by itself |
| Confidentiality | Low | Discloses internal network/version data |
| Integrity | None | Read-only |
| Availability | None | No disruption |

**CVSS Score: 5.3 (Medium / P3)**

Note: Severity escalates to High (P2) if chained with an SSRF vulnerability, as the disclosed pod IPs become direct attack targets.

---

## Remediation

1. **Restrict status endpoints to internal networks only:** Apply network-level access controls (Kubernetes NetworkPolicy, API Gateway IP allowlist, or ingress annotation) to limit `/api/status` and `/api/v2/status` access to internal IP ranges only (`10.0.0.0/8`).

2. **Authenticate diagnostic endpoints:** Require an internal service token or mutual TLS for any endpoint that returns environment or version metadata.

3. **Sanitize status endpoint response:** If the endpoint must remain accessible externally (e.g., for uptime monitoring), strip internal infrastructure fields: `machineIp`, `machineName`, `commit`, `branch`, `infraVersion`. Return only `statusCode: 200` and `applicationName`.

4. **Use Kubernetes liveness/readiness probes internally:** Configure K8s probes to use the internal cluster DNS rather than exposing diagnostic routes through the public ingress controller.

**Example minimal safe response:**
```json
{
  "status": "healthy",
  "statusCode": 200
}
```

---

## Timeline

- 2026-09-02: Both endpoints discovered via passive reconnaissance of `*.etoro.com` subdomains
- 2026-09-02: Confirmed unauthenticated access; no exploitation performed
- 2026-09-02: Reported via Bugcrowd

---

*Reported by: komeng rooket | Bugcrowd eToro Program*

---

## Update: Additional Affected Service — KYC Proxy (`kyc.etoro.com`)

**Discovered during expanded reconnaissance:** `kyc.etoro.com` hosts a KYC (Know Your Customer) proxy service that exposes the same unauthenticated status endpoint pattern. The KYC Proxy handles identity verification for eToro users — a significantly higher-sensitivity service than the Affiliate API.

### 3. KYC Proxy — `kyc.etoro.com/api/status` and `kyc.etoro.com/api/v1/status`

**Request:**
```http
GET /api/status HTTP/1.1
Host: kyc.etoro.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Bug-Bounty: komeng rooket
```

**Response (HTTP 200 — No Authentication Required):**
```json
{
  "application": {
    "applicationName": "KYCProxy",
    "uptimeInSeconds": 604066.0
  },
  "environment": {
    "region": "WestEur",
    "machineName": "kycproxy-67f6b98b68-xlx7b",
    "machineIp": "10.204.73.117"
  },
  "version": {
    "version": "v1.219.0",
    "infraVersion": "10.2.8+9a28f188921a0041a3841ae43b99e5a3aea8e46b",
    "chartVersion": "v1.217.0",
    "commit": "bab5d0260bc3b6c574f6f34be3902d8a61aba90a",
    "branch": "master"
  },
  "statusCode": 200
}
```

**cURL Proof:**
```bash
curl -s https://kyc.etoro.com/api/status \
  -H "X-Bug-Bounty: komeng rooket"
```

**Enhanced Impact:** The `applicationName: "KYCProxy"` designation reveals this is the proxy layer for eToro's identity verification system, which processes government-issued ID documents, biometric verification, and personal identity data. The exposure of:
- Internal pod IP `10.204.73.117` (a third unique internal IP across findings)
- KYCProxy version `v1.219.0`
- Helm chart version `v1.217.0` (adds Kubernetes chart versioning data)
- Git commit from `master` branch

...on the system that handles user identity documents elevates the combined severity of this finding pattern from P3 to **P2 (High)** based on the cumulative impact of internal network enumeration across multiple highly sensitive microservices.

### Systemic Finding Summary

| Service | Subdomain | Internal IP | Pod Name | Application |
|---------|-----------|-------------|----------|-------------|
| Affiliate API | `affapi.etoro.com` | `10.203.85.110` | `aff-api-f-5f5dbd5f7b-bjpq5` | Partners |
| Client Logs API | `etorologsapi.etoro.com` | `10.204.83.206` | `client-logs-api-5bcdc6765-64fgm` | ClientLogsApi |
| KYC Proxy | `kyc.etoro.com` | `10.204.73.117` | `kycproxy-67f6b98b68-xlx7b` | KYCProxy |

All three services share the same unauthenticated diagnostic endpoint pattern (`/api/status`, `/api/v1/status`), indicating a systemic misconfiguration across eToro's microservices platform rather than an isolated issue.

**Revised CVSS Score for Combined Finding: 7.5 (High / P2)**
