# Bugcrowd Finding #19 — CSP Misconfiguration on blog.nu.com.mx (script-src: https:) and blog.nu.com.co (unsafe-inline) + Cross-TLD CORS Chain

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P2 High
**Severity (Chained):** P1 Critical — XSS on Mexico/Colombia blog → CORS with credentials on ALL prod APIs (Brazil, Mexico, Colombia) via cross-TLD trust
**VRT:** Server Security Misconfiguration > Content Security Policy
**Related:** Finding #4 (blog.nubank.com.br CSP), Finding #2 (cross-TLD CORS), Finding #8 (CORS mx/co)

---

## Summary

The Nubank blog for Mexico (`blog.nu.com.mx`) has a critically weak Content Security Policy: `script-src: https:` — a wildcard that allows scripts from **any HTTPS URL**. The Colombia blog (`blog.nu.com.co`) uses `'unsafe-inline'` in `script-src`. Both are trusted by Nubank's Istio CORS configuration with `access-control-allow-credentials: true` — on **all three national prod API clusters** (Brazil, Mexico, Colombia) due to the cross-TLD CORS regex (Finding #2).

---

## Technical Evidence

### 1. blog.nu.com.mx — script-src: https: (All HTTPS Origins Permitted)

```bash
curl -sI "https://blog.nu.com.mx/" -H "X-Correlation-Id: bc-handle"
```

**Relevant CSP:**
```
content-security-policy:
  script-src https: cdn.ampproject.org analytics.tiktok.com 
             connect.facebook.net www.googletagmanager.com ...
             'unsafe-inline' 'unsafe-eval' blob: data:;
```

The `script-src: https:` directive is a **wildcard for all HTTPS origins**. This means:
- Any script hosted at any HTTPS URL can be loaded (`<script src="https://attacker.com/evil.js">`)
- `'unsafe-inline'` is also present — inline scripts execute without restriction
- `'unsafe-eval'` is also present — `eval()` is unrestricted

This CSP provides **no XSS protection** — it only prevents loading HTTP (not HTTPS) scripts.

### 2. blog.nu.com.co — script-src: 'unsafe-inline'

```bash
curl -sI "https://blog.nu.com.co/" -H "X-Correlation-Id: bc-handle"
```

**Relevant CSP:**
```
content-security-policy:
  script-src 'self' 'unsafe-inline' https://cdn.ampproject.org/ 
             https://connect.facebook.net/ https://analytics.tiktok.com/ 
             https://www.googletagmanager.com/ https://widgets.wp.com/ 
             https://secure.gravatar.com/ https://stats.wp.com https://s0.wp.com/ data:;
```

`'unsafe-inline'` allows execution of any `<script>…</script>` block or event handler without a nonce.

### 3. Cross-TLD CORS Trust — Both Blogs Trusted by All Prod API Clusters

```bash
# blog.nu.com.co trusted by BRAZIL prod API (cross-TLD!)
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://blog.nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://blog.nu.com.co
# access-control-allow-credentials: true

# blog.nu.com.co trusted by COLOMBIA prod API
curl -sI "https://prod-global-auth.nu.com.co/" \
  -H "Origin: https://blog.nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://blog.nu.com.co
# access-control-allow-credentials: true

# blog.nu.com.mx trusted by MEXICO prod API (from Finding #8)
# access-control-allow-origin: https://blog.nu.com.mx
# access-control-allow-credentials: true
```

---

## Attack Chain

```
[Blog Mexico — blog.nu.com.mx]

[Step 1] XSS on blog.nu.com.mx
  ↓ script-src: https: → any HTTPS URL is a valid script source
  ↓ 'unsafe-inline' → reflected/stored inline XSS also executes
  ↓ No nonce required

[Step 2] Attacker's script executes on blog.nu.com.mx origin
  ↓ fetch('https://prod-global-auth.nu.com.mx/api/v1/user', {credentials:'include'})
  ↓ CORS: blog.nu.com.mx origin → allowed with credentials
  ↓ User's authenticated session token sent to Mexico prod auth

[Step 3] Data exfiltrated:
  → Mexican customer PII (CURP, name, RFC, phone, email)
  → Credit/debit account info
  → Authentication token for further access

---

[Blog Colombia — blog.nu.com.co]

[Step 1] XSS on blog.nu.com.co
  ↓ 'unsafe-inline' → any injected script executes
  ↓ No nonce required

[Step 2] Attacker's inline script executes on blog.nu.com.co origin
  ↓ fetch('https://prod-global-auth.nubank.com.br/api/v1/user', {credentials:'include'})
  ↓ CORS: blog.nu.com.co → TRUSTED BY BRAZIL prod API (cross-TLD!)
  ↓ Colombian and Brazilian user sessions both accessible from Colombia blog XSS

[Impact] XSS on Colombia/Mexico blog enables access to authenticated data
         across ALL Nubank countries (Brazil, Mexico, Colombia) via cross-TLD CORS
```

---

## Comparison: All Nubank Blog CSP Issues

| Blog Domain | script-src Issue | CORS with Credentials | Combined Severity |
|------------|------------------|-----------------------|-------------------|
| `blog.nubank.com.br` | `script-src-elem: *` (all external) | All prod APIs (*.nubank.com.br trust) | P1 Critical chain |
| `blog.nu.com.mx` | `script-src: https:` (all HTTPS) | All prod APIs (cross-TLD) | **P1 Critical chain** |
| `blog.nu.com.co` | `'unsafe-inline'` | All prod APIs (cross-TLD) | **P1 Critical chain** |
| `lp.blog.nubank.com.br` | `script-src-elem: *` (all external) | All prod APIs (*.nubank.com.br trust) | P1 Critical chain |
| `backend.blog.nubank.com.br` | `script-src-elem: *` (all external) | All prod APIs (*.nubank.com.br trust) | P1 Critical chain |
| `blog-nubank-com-br-develop.go-vip.net` | `script-src-elem: *` (all external) | All prod APIs (*.go-vip.net trust) | P2 High chain |

---

## Remediation

| Blog | Fix |
|------|-----|
| `blog.nu.com.mx` | Remove `https:` from `script-src` — replace with explicit CDN allowlist + nonce-based policy |
| `blog.nu.com.co` | Remove `'unsafe-inline'` — implement nonce-based CSP |
| `blog.nubank.com.br` | Remove `script-src-elem: *` — explicit CDN list + nonce |
| All blogs | Apply strict `script-src` with nonce for WordPress VIP (WordPress VIP supports CSP nonces) |

---

## Notes

- All analysis via `curl -sI` HEAD requests
- WordPress XML-RPC is also active on all these blogs (`system.multicall` — see Finding #13)
- All requests used `X-Correlation-Id: bc-handle` as required

