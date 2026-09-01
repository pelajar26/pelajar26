# Bugcrowd Finding #6 — Easynvest API Information Disclosure (Git Hash + CORS + UA Reflection)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P3 Medium (CORS subdomain reflection without credentials) / P4 Low (git hash, UA reflection)
**Target:** `www.nuinvest.com.br` (Nubank / former Easynvest)
**VRT:** Server Security Misconfiguration > Information Exposure

---

## Summary

The `www.nuinvest.com.br/api` endpoint exposes multiple information disclosure issues:
1. **Git commit hash disclosure** via `/api/version` — full SHA-1 hash of deployed code
2. **CORS wildcard subdomain reflection** — any `*.nuinvest.com.br` origin is reflected (no `credentials: true`, but enables data exfiltration if XSS exists)
3. **User-Agent content injection** — arbitrary text injected into response body
4. **Client IP spoofing via X-Forwarded-For** — API trusts X-Forwarded-For for IP display
5. **Internal trace ID disclosure** via `Server-Timing: intid;desc=<hex>` header on all responses

---

## Technical Evidence

### 1. Git Commit Hash Disclosure

```bash
curl -s "https://www.nuinvest.com.br/api/version" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```json
{"version":"a5b9081f6695e6a368c9e56274c285e3d317861c"}
```

**Impact:** 
- An attacker can correlate the commit hash against public/leaked git repositories to enumerate code changes, identify specific vulnerable versions, or enumerate code paths.
- Combined with other recon data, enables precise timing of when security fixes were deployed.

---

### 2. CORS Wildcard Subdomain Reflection (*.nuinvest.com.br)

```bash
curl -si "https://www.nuinvest.com.br/api" \
  -H "Origin: https://evil.nuinvest.com.br" \
  -H "X-Correlation-Id: bc-handle"
```
**Response headers:**
```
access-control-allow-origin: https://evil.nuinvest.com.br
access-control-expose-headers: X-Frame-Options, Transfer-Encoding, Server-Timing, ...
```

**Notable:** External origins (e.g., `attacker.com`) receive `Forbidden`, but ANY `*.nuinvest.com.br` subdomain is reflected. This means:
- If a subdomain of `nuinvest.com.br` can be taken over or XSS can be injected, cross-origin read of the API becomes possible.
- `access-control-expose-headers` exposes all response headers cross-origin, including internal `Server-Timing` trace IDs.
- **`access-control-allow-credentials` is NOT present** — session cookies are not exfiltrable (unlike Finding #2 on prod-* endpoints).

---

### 3. User-Agent Content Injection

```bash
curl -s "https://www.nuinvest.com.br/api" \
  -H "User-Agent: INJECTED_TEXT_HERE" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
Easynvest API is online O.S: INJECTED_TEXT_HERE IpAddress: <client-ip>
```

**Response Content-Type:** `text/plain;charset=utf-8` — browsers will not execute script content, so XSS via this vector is not possible. However, this could be used for:
- Log injection (if logs contain this response)
- Social engineering (custom text displayed in response)
- Detection of WAF bypass patterns

---

### 4. X-Forwarded-For Trusted for IP Display

```bash
curl -s "https://www.nuinvest.com.br/api" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
Easynvest API is online O.S: curl/8.5.0 IpAddress: 127.0.0.1
```

The API trusts `X-Forwarded-For` for IP display. While this endpoint doesn't appear to perform IP-based access control, the pattern suggests similar trust may exist in other Easynvest/Nuinvest backend services.

---

### 5. Internal Trace ID via Server-Timing

All responses include:
```
server-timing: intid;desc=caab8f1d477f29a3
```

`intid` is a unique internal trace/request ID exposed in every response. While not immediately exploitable, it leaks internal request correlation information that could aid in:
- Timing attacks
- Request correlation for support escalation or insider threat scenarios

---

## Platform Notes

`www.nuinvest.com.br` runs "Easynvest API" — this is Nubank's acquired investment platform (Easynvest, rebranded as NuInvest). The platform appears to be running a separate stack from the main Nubank backend, with different CORS policies, CSP (`'unsafe-inline' 'unsafe-eval'`), and information exposure characteristics.

The CSP on nuinvest.com.br is:
```
script-src 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' https: http:
```
Note: `http:` is allowed — scripts from any non-HTTPS origin can be loaded, which is a significant CSP weakness.

---

## Remediation

| Issue | Fix |
|-------|-----|
| Git hash in /api/version | Remove or restrict to internal networks only |
| CORS subdomain reflection | Use explicit allowlist of specific origins |
| User-Agent echo | Remove O.S. and IpAddress from public response |
| X-Forwarded-For trust | Validate XFF against known proxy IP ranges only |
| Server-Timing trace ID | Remove from production responses or restrict to internal |
| CSP http: in script-src | Replace with `https:` only; remove `'unsafe-inline'` and `'unsafe-eval'` |

---

## Notes

- All requests used `X-Correlation-Id: bc-handle` as required
- No authentication was required for these endpoints
- No exploitation beyond passive observation was performed
