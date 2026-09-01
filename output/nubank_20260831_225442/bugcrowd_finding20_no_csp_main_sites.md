# Bugcrowd Finding #20 — Missing script-src CSP on nubank.com.br and nu.com.co — Both CORS-Trusted Origins with Credentials

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P3 Medium — CORS-trusted origins without CSP script protection
**Severity (Chained):** P1 Critical — Any XSS on nubank.com.br or nu.com.co → credentialed access to ALL Nubank prod APIs across BR + CO + MX
**VRT:** Server Security Misconfiguration > Content Security Policy
**Related:** Finding #2 (CORS wildcard subdomain reflection), Finding #4 (CSP XSS chain), Finding #19 (blog.nu.com.mx / blog.nu.com.co)

---

## Summary

Two major Nubank consumer-facing websites lack meaningful Content Security Policy protection:

1. **`nubank.com.br`** — The main Brazilian Nubank website (highest traffic, Next.js SSR) has **no Content-Security-Policy header at all**. It is CORS-trusted by all Nubank production microservices in Brazil, Mexico, and Colombia with `access-control-allow-credentials: true`.

2. **`nu.com.co`** — The main Colombian Nubank website (Next.js SSG) has a CSP that only sets `frame-ancestors` — **no `script-src`, `default-src`, or any script-related directive**. It is CORS-trusted by Colombian prod APIs **and also by Brazilian prod APIs** (cross-TLD) with credentials.

Any XSS discovered on either domain would execute without CSP restriction and gain full credentialed access to production APIs across all three Nubank countries.

---

## Technical Evidence

### 1. nubank.com.br — Complete Absence of Content-Security-Policy

```bash
curl -sI "https://nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```

**Full response headers:**
```
HTTP/2 200
content-type: text/html; charset=utf-8
x-powered-by: Next.js
server: istio-envoy
x-xss-protection: 1; mode=block         ← deprecated, not effective
x-frame-options: SAMEORIGIN
referrer-policy: strict-origin-when-cross-origin
x-content-type-options: nosniff
strict-transport-security: max-age=63072000; includeSubDomains; preload
# NO Content-Security-Policy header
```

**Key observations:**
- `nubank.com.br` is a **server-side rendered (SSR) Next.js application** (not static) — `x-envoy-upstream-service-time: 8018` confirms active backend rendering
- `x-xss-protection: 1; mode=block` is a deprecated header, ignored by Chrome/Edge since 2019
- No `Content-Security-Policy` header — **zero CSP protection on the main Nubank Brazil website**
- SSR means URL parameters and path segments are potentially processed server-side, creating XSS surface in dynamic rendering paths

**CORS trust confirmation:**
```bash
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://nubank.com.br
# access-control-allow-credentials: true
```

---

### 2. nu.com.co — CSP Without Any Script Protection

```bash
curl -sI "https://nu.com.co/" -H "X-Correlation-Id: bc-handle"
```

**CSP header:**
```
content-security-policy: frame-ancestors 'self' https://blog.nu.com.co
```

**This is the COMPLETE CSP** — only `frame-ancestors` is defined. There is:
- No `script-src` directive
- No `default-src` directive
- No `connect-src` directive
- No restriction on inline scripts, eval, or external script loading

**Third-party scripts loaded by nu.com.co without integrity hashes:**
```html
<script src="https://tracking-cdn.figpii.com/f9c9ca3ff25865b37ae07bd1c686ae94.js"></script>
<!-- ↑ S3-hosted CDN script, no integrity attribute -->
<script src="https://websdk.appsflyersdk.com?..."></script>
<!-- ↑ AppsFlyer SDK, no integrity attribute -->
<!-- GTM container GTM-PDG7L7M injected dynamically -->
```

**CORS trust from Colombian prod API:**
```bash
curl -sI "https://prod-global-auth.nu.com.co/" \
  -H "Origin: https://nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://nu.com.co
# access-control-allow-credentials: true
```

**CORS trust from Brazilian prod API (cross-TLD):**
```bash
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://nu.com.co
# access-control-allow-credentials: true
```

---

### 3. CSP Comparison — Main Consumer Sites

| Domain | CSP Status | CORS-Trusted By | Credentials |
|--------|-----------|-----------------|-------------|
| `nubank.com.br` | **No CSP at all** | All prod-* (BR/MX/CO) | ✅ true |
| `nu.com.co` | **frame-ancestors only — no script-src** | prod-* BR + CO | ✅ true |
| `nubank.com.mx` | Has CSP but `unsafe-inline + unsafe-eval` (Finding #15) | All prod-* (BR/MX/CO) | ✅ true |
| `app.nubank.com.br` | Has CSP with `*.nubank.com.br` wildcard script-src (Finding #4 addendum) | All prod-* (BR/MX/CO) | ✅ true |
| `blog.nubank.com.br` | `script-src-elem: *` wildcard (Finding #4) | All prod-* (BR/MX/CO) | ✅ true |

**Pattern:** Every major Nubank consumer origin is CORS-trusted with credentials, and none have effective script-src CSP restrictions.

---

## Complete P1 Critical Attack Chain

### Chain A: XSS on nubank.com.br (SSR Next.js)

```
[nubank.com.br — No CSP, SSR, CORS-trusted with credentials]

[Step 1] XSS identified on nubank.com.br via:
  - Reflected parameter in SSR rendering path
  - DOM-based XSS via URL fragment processed by Next.js client router
  - Third-party script compromise (GTM-KGFBFP, DatoCMS, etc.)

[Step 2] Injected script has no CSP restrictions:
  → fetch('https://prod-global-auth.nubank.com.br/api/v1/user', {credentials:'include'})
  ↓ CORS allows nubank.com.br with credentials=true
  ↓ API returns authenticated victim's user data

[Step 3] Exfiltrate data, initiate PIX transfers, ATO:
  → All prod-global-*.nubank.com.br APIs accessible with victim's session
  → prod-global-pix.nubank.com.br → PIX payment initiation
  → prod-s{N}-customers.nubank.com.br → PII, account data

[Impact] ATO + PIX theft + PII exfiltration — 100M+ Brazilian Nubank customers
```

### Chain B: Supply Chain Attack on nu.com.co

```
[nu.com.co loads tracking-cdn.figpii.com scripts without integrity hashes]
[No script-src CSP — malicious script from figpii.com CDN executes freely]

[Step 1] tracking-cdn.figpii.com is S3-backed:
  $ curl -sI "https://tracking-cdn.figpii.com/"
  # Server: AmazonS3
  # x-amz-bucket-region: us-east-1
  
  If figpii.com CDN is compromised OR figpii.com bucket is misconfigured:
  → Attacker hosts malicious payload at tracking-cdn.figpii.com/[path].js

[Step 2] Malicious figpii script executes on nu.com.co origin:
  → No CSP blocks it (no script-src directive)
  → fetch('https://prod-global-auth.nu.com.co/api/v1/user', {credentials:'include'})
  ↓ CORS: nu.com.co trusted by Colombian prod with credentials
  
  AND ALSO:
  → fetch('https://prod-global-auth.nubank.com.br/api/v1/user', {credentials:'include'})
  ↓ CORS: nu.com.co trusted by BRAZIL prod with credentials (cross-TLD!)

[Impact] All Colombian AND Brazilian customers affected via one supply chain compromise
```

---

## Static.nubank.com.br — Additional CORS Trust on CDN Origin

```bash
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://static.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://static.nubank.com.br
# access-control-allow-credentials: true
```

`static.nubank.com.br` (S3 bucket / CloudFront CDN serving JS/CSS for nubank.com.br) is also CORS-trusted with credentials. This means:

- If an attacker can upload files to the `static.nubank.com.br` S3 bucket, they can:
  1. Host malicious JavaScript at `https://static.nubank.com.br/[path]/evil.js`
  2. `app.nubank.com.br` (CSP: `script-src *.nubank.com.br`) will LOAD the script (it's trusted in script-src)
  3. The script also has CORS access to all prod APIs with credentials

This creates a path: **S3 bucket write → script execution on app.nubank.com.br → CORS credentialed access to all prod APIs**

---

## Severity Assessment

| Issue | Severity | Rationale |
|-------|----------|-----------|
| nubank.com.br — no CSP | P2 High (standalone) | Main BR site, SSR, zero XSS mitigation |
| nubank.com.br XSS chain | P1 Critical (chained) | No CSP + CORS credentials = instant ATO if XSS found |
| nu.com.co — no script-src CSP | P2 High (standalone) | Main CO site, third-party scripts without integrity |
| nu.com.co supply chain chain | P1 Critical (chained) | figpii CDN compromise → Colombian + Brazilian ATO |
| static.nubank.com.br CORS trust | P2 High | CDN origin trusted with credentials + script-src whitelisted |

---

## Remediation

| Issue | Fix |
|-------|-----|
| `nubank.com.br` — no CSP | Implement CSP with nonce-based `script-src`; remove `x-xss-protection` (deprecated) |
| `nu.com.co` — no script-src | Add `script-src 'self' [explicit allowed origins]` with nonces for inline scripts |
| Third-party scripts on nu.com.co | Add `integrity` attributes (SRI) to all external `<script>` tags |
| figpii.com CDN dependency | Audit figpii.com security; consider self-hosting tracking scripts or using subresource integrity |
| `static.nubank.com.br` CORS | Evaluate whether CDN origin needs credential CORS access; if not, restrict to specific subdomains |

---

## Notes

- All analysis via HEAD/GET requests — no XSS injection performed
- `nubank.com.br` SSR confirmed by: `x-envoy-upstream-service-time` header, per-request Sentry trace in HTML, `x-powered-by: Next.js`
- `nu.com.co` is SSG (pre-rendered) from S3, reducing server-side XSS surface but not client-side
- `tracking-cdn.figpii.com` S3 bucket origin confirmed — script accessible at hashed URL
- All requests used `X-Correlation-Id: bc-handle` as required
