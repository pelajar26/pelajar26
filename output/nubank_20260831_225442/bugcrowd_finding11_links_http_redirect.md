# Bugcrowd Finding #11 — links.nubank.com.br HTTPS Redirects to HTTP (No HSTS — Credential Interception Risk)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P3 Medium (internal portal credential interception risk)
**Target:** `links.nubank.com.br` (Intaface — internal link management / email tracking system)
**VRT:** Transport Layer Security > Missing HSTS

---

## Summary

`links.nubank.com.br` runs an internal Intaface (email marketing link management) portal. When accessed over HTTPS, it issues a 302 redirect to the same domain but over **HTTP** (`http://links.nubank.com.br/login?ReturnUrl=%2F`) — without a Strict-Transport-Security (HSTS) header. This creates an SSL stripping risk for internal Nubank employees accessing this portal on non-HTTPS networks.

---

## Technical Evidence

### HTTPS to HTTP Redirect

```bash
curl -sI "https://links.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 302
location: http://links.nubank.com.br/login?ReturnUrl=%2F
server: csw
```

Note: **No `Strict-Transport-Security` header** in the HTTPS response.

### HTTP Endpoint Behavior

```bash
curl -sI "http://links.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/1.1 301 Moved Permanently
location: https://links.nubank.com.br/login
```

HTTP redirects back to HTTPS at the root, but the HTTPS login page itself then redirects to HTTP — creating a redirect loop that exposes credentials during the HTTP step.

### Login Page (HTTPS)

```bash
curl -sI "https://links.nubank.com.br/login" -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 200
server: csw
set-cookie: cs_siftsession=...; path=/; secure; SameSite=None
set-cookie: cs_siftsession=[value]; path=/; secure; SameSite=None
x-frame-options: SAMEORIGIN
```

While the session cookie has the `Secure` flag (will not be transmitted over HTTP), the login page itself is rendered over HTTP at `http://links.nubank.com.br/login` — meaning form submission targets could be exposed.

---

## Portal Identification

The portal is identified as **Intaface** (Campaign Monitor's link management and email tracking platform):

```html
<title>Log In | Intaface</title>
<div class="js-app" 
  data-siteKeyV3="6LdsO5wcAAAAADQa6KRAAvZHz-NoYpAcj591zhQK"
  data-siteName="Intaface"
  data-logoUrl="https://img.createsend1.com/static/logos/i/340E2A99/login/intaface-color-transp.png"
/>
```

An XML API is exposed at `https://links.nubank.com.br/api/`:
```bash
curl -s "https://links.nubank.com.br/api/" -H "X-Correlation-Id: bc-handle"
# Response: <?xml version="1.0" encoding="utf-8"?>
# <Result><Code>50</Code><Message>Must supply a valid HTTP Basic Authorization header</Message></Result>
```

The API uses HTTP Basic Authentication — credential interception over HTTP is the primary concern.

---

## Risk

An internal Nubank employee accessing `links.nubank.com.br` from a network where an attacker can perform an SSL stripping attack (e.g., corporate Wi-Fi, VPN split tunneling, internal network MITM) would:

1. Initial HTTPS request made by browser
2. HTTPS 302 redirect to `http://links.nubank.com.br/login?ReturnUrl=/`
3. If HSTS is not enforced (no preload list), browser follows to HTTP
4. Login credentials submitted over cleartext HTTP
5. Attacker intercepts HTTP Basic Auth credentials and/or session cookie

Without HSTS with preload, first-time visitors or visitors on untrustworthy networks are vulnerable.

---

## Remediation

1. **Fix the redirect:** The HTTPS application should NOT redirect to HTTP — change the redirect target to `https://links.nubank.com.br/login?ReturnUrl=%2F`
2. **Add HSTS:** Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses from `links.nubank.com.br`
3. **Submit to HSTS Preload list:** If HSTS max-age is set correctly, submit to `https://hstspreload.org`
4. **Restrict access:** If `links.nubank.com.br` is an internal-only tool, consider IP allowlisting to corporate network ranges rather than public internet exposure

---

## Notes

- No credentials were submitted — only passive header analysis
- The Secure flag on `cs_siftsession` cookie partially mitigates cookie theft, but the login form itself being rendered over HTTP remains a risk
- All requests used `X-Correlation-Id: bc-handle` as required
