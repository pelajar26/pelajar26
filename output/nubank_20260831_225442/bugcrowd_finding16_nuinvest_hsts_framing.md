# Bugcrowd Finding #16 — NuInvest HSTS Disabled (max-age=0) + Overly Permissive frame-ancestors

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P3 Medium (HSTS disabled) / P2 High (frame-ancestors + XSS chain from Finding #4)
**Target:** `www.nuinvest.com.br`, `api.nuinvest.com.br`, `nuinvest.com.br`
**VRT:** Server Security Misconfiguration > HTTP Security Headers

---

## Summary

All `nuinvest.com.br` subdomains serve `Strict-Transport-Security: max-age=0; includeSubDomains` — a directive that **actively disables HSTS** for the entire nuinvest.com.br domain. This contrasts with nubank.com.br (2-year HSTS + preload) and nubank.com.mx (1-year HSTS), which are properly configured.

Additionally, `www.nuinvest.com.br` (the investment platform) allows itself to be embedded in an iframe from **any `*.nubank.com.br` or `*.nuinvest.com.br` subdomain** via `frame-ancestors`. When chained with XSS vulnerabilities documented in Finding #4 (comunidade.nubank.com.br, blog.nubank.com.br), this enables clickjacking attacks against the NuInvest brokerage platform.

---

## Technical Evidence

### 1. HSTS max-age=0 — HSTS Disabled Across All nuinvest.com.br

```bash
curl -sI "https://www.nuinvest.com.br/" -H "X-Correlation-Id: bc-handle"
# strict-transport-security: max-age=0; includeSubDomains

curl -sI "https://api.nuinvest.com.br/" -H "X-Correlation-Id: bc-handle"
# strict-transport-security: max-age=0; includeSubDomains

curl -sI "https://nuinvest.com.br/" -H "X-Correlation-Id: bc-handle"
# strict-transport-security: max-age=0; includeSubDomains
```

**Comparison with other Nubank properties:**

| Domain | HSTS | Status |
|--------|------|--------|
| `nubank.com.br` | `max-age=63072000; includeSubDomains; preload` | ✅ Correct |
| `nubank.com.mx` | `max-age=31536000` | ✅ Correct |
| `blog.nubank.com.br` | `max-age=31536000` | ✅ Correct |
| `blog.nu.com.mx` | `max-age=31536000` | ✅ Correct |
| **`nuinvest.com.br`** | **`max-age=0; includeSubDomains`** | **❌ HSTS DISABLED** |
| **`www.nuinvest.com.br`** | **`max-age=0; includeSubDomains`** | **❌ HSTS DISABLED** |
| **`api.nuinvest.com.br`** | **`max-age=0; includeSubDomains`** | **❌ HSTS DISABLED** |

**Impact of `max-age=0`:**
- `max-age=0` instructs browsers to **remove** nuinvest.com.br from their HSTS cache
- The `includeSubDomains` parameter extends this removal to ALL nuinvest.com.br subdomains
- Without HSTS, users who navigate to `http://nuinvest.com.br` over an insecure network (public Wi-Fi, MitM position) are vulnerable to SSL stripping attacks
- An attacker with network access can intercept HTTP connections before the redirect to HTTPS

**Likely cause:** During the Easynvest → NuInvest rebrand/migration, the CloudFlare HSTS configuration was set to `max-age=0` to clear HSTS (perhaps to allow HTTP testing during migration) and was never restored.

---

### 2. frame-ancestors — NuInvest Embeddable from Any *.nubank.com.br Subdomain

```bash
curl -sI "https://www.nuinvest.com.br/" -H "X-Correlation-Id: bc-handle"
# content-security-policy: frame-ancestors nuinvest.com.br *.nuinvest.com.br nubank.com.br *.nubank.com.br
# x-frame-options: SAMEORIGIN
```

The `frame-ancestors` CSP header allows embedding `www.nuinvest.com.br` from:
- ANY `*.nubank.com.br` subdomain (very broad — 200+ subdomains)
- ANY `*.nuinvest.com.br` subdomain

The `X-Frame-Options: SAMEORIGIN` conflicts with the CSP `frame-ancestors` policy — in modern browsers supporting CSP3, `frame-ancestors` takes precedence, so blog.nubank.com.br **CAN** embed www.nuinvest.com.br despite SAMEORIGIN.

---

### 3. Clickjacking Chain — XSS on Blog → NuInvest Clickjacking

```
[Prerequisite] XSS on blog.nubank.com.br (Finding #4 — script-src-elem: *, unsafe-inline)
  OR XSS on comunidade.nubank.com.br (Finding #4 — no script-src directive)

[Step 1] XSS payload on blog.nubank.com.br embeds NuInvest investment app:
  <iframe src="https://www.nuinvest.com.br/investimentos/negociar" 
          style="position:fixed;top:0;left:0;width:100%;height:100%;opacity:0.01;z-index:999">
  </iframe>
  ↓ CSP frame-ancestors allows *.nubank.com.br → iframe loads!

[Step 2] Attacker overlay positioned over sensitive financial actions:
  - "Comprar" (Buy stock) button at predicted coordinates
  - "Sacar" (Withdraw funds) confirmation
  - "Autorizar PIX" (Authorize transfer) button

[Step 3] User on blog.nubank.com.br clicks "Like" or other blog UI
  ↓ Real click lands on invisible NuInvest iframe button
  ↓ Unauthorized stock trade or fund withdrawal executed
  
[Impact] Unauthorized financial transactions on NuInvest brokerage platform
```

---

### 4. api.nuinvest.com.br — IP and User-Agent Disclosure in Response Body

```bash
curl -s "https://api.nuinvest.com.br/" -H "X-Correlation-Id: bc-handle"
# Response: "Easynvest API is online O.S: curl/8.5.0 IpAddress: 160.79.106.132"
```

The health endpoint reflects:
- **Client IP address** directly in response body
- **User-Agent string** (labeled as "O.S:") in response body

**Note:** "Easynvest API is online" confirms this is a legacy endpoint from the Easynvest brand (acquired by Nubank 2021) still running under nuinvest.com.br. The IP disclosure is low-risk (IP is visible to the server anyway), but reflects poor security hygiene on a financial API.

---

## Severity Assessment

| Issue | Severity | Rationale |
|-------|----------|-----------|
| HSTS max-age=0 | P3 Medium | Enables SSL stripping on insecure networks for nuinvest.com.br users |
| frame-ancestors *.nubank.com.br | P3 Medium (standalone) | Overly broad framing policy on financial platform |
| frame-ancestors + blog XSS chain | P2 High (chained) | Enables clickjacking on brokerage actions using XSS from Finding #4 |
| IP reflection in api response | P5 Informational | Low risk, but unnecessary data exposure |

---

## Remediation

| Issue | Fix |
|-------|-----|
| HSTS max-age=0 | Set `max-age=31536000; includeSubDomains; preload` on all nuinvest.com.br properties |
| frame-ancestors | Replace `*.nubank.com.br *.nuinvest.com.br` with explicit trusted origins only (e.g., specific pages of app.nubank.com.br if SSO embedding is required) |
| api.nuinvest.com.br response | Remove IP address and User-Agent from the health endpoint response body |
| Legacy Easynvest API | Audit api.nuinvest.com.br for other legacy misconfigurations from the Easynvest era |

---

## Notes

- All tests passive (HTTP HEAD/GET requests only)
- No authentication performed on NuInvest platform
- No iframe clickjacking was executed — attack path documented based on CSP policy observation
- All requests used `X-Correlation-Id: bc-handle` as required
