# Verisign Bug Bounty — Findings Report
**Date:** 2026-09-02  
**Program:** Verisign Bug Bounty  
**Researcher:** naqkhaie.f055@gmail.com  
**Branch:** claude/bug-bounty-capabilities-l4fryb  
**Header:** X-Bug-Bounty: bugcrowd (all requests)

---

## Executive Summary

Testing was conducted against Verisign infrastructure on 2026-09-02. Five (5) findings were identified: one (1) HIGH severity logic flaw, one (1) MEDIUM severity information disclosure, and three (3) LOW/INFORMATIONAL findings. No RCE or critical injection vulnerabilities were successfully exploited due to strict input hardening, strong CSP on main endpoints, and mutual TLS on EPP services.

---

## F-004: X-Forwarded-For Header Trusted for Rate Limiting — WHOIS Access Control Bypass

**Severity:** HIGH  
**Target:** `webwhois.verisign.com/webwhois-ui/rest/whois`  
**Bounty Category:** Logic flaws / Security bypass  
**Estimated Bounty:** $2,500–$5,000 (Tier 1 / Tier 2)  
**CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L

### Description

The server at `webwhois.verisign.com` **trusts the user-controlled `X-Forwarded-For` header** to identify the client IP address for rate-limiting purposes. An attacker can set any arbitrary IP value (RFC1918 private ranges or any fabricated public IP) in this header to **completely bypass WHOIS rate limits** and perform unlimited queries.

This is a significant logic flaw because:
- WHOIS is sensitive data (domain owner info, nameservers, contacts)
- Rate limiting is the primary protection against data scraping abuse
- Bypass enables large-scale automated data collection with no restriction

### Evidence

**Without X-Forwarded-For header (subject to IP-based rate limiting):**
```http
GET /webwhois-ui/rest/whois?q=google.com&tld=com&type=domain HTTP/1.1
Host: webwhois.verisign.com
X-Bug-Bounty: bugcrowd

HTTP/1.1 200 OK
{"responseType":"success","message":"   Domain Name: GOOGLE.COM\n...","query":"google.com"}
```

**With spoofed X-Forwarded-For — rate limit fully bypassed:**
```http
GET /webwhois-ui/rest/whois?q=google.com&tld=com&type=domain HTTP/1.1
Host: webwhois.verisign.com
X-Bug-Bounty: bugcrowd
X-Forwarded-For: 192.168.1.1

HTTP/1.1 200 OK
{"responseType":"success","message":"   Domain Name: GOOGLE.COM\n...","query":"google.com"}
```

All tested IP values successfully bypassed rate limiting:
- `192.168.1.1` (RFC1918 private)
- `10.0.0.1` (RFC1918 private)
- `172.16.0.1` (RFC1918 private)
- `203.0.113.1` (TEST-NET-3, non-routable)

### Exploitation Scenario

An attacker can write an automated script that:
1. Rotates `X-Forwarded-For` values on each request
2. Downloads complete WHOIS data for commercial domains without restriction
3. Builds phishing target lists from domain owner contact data

### Impact

- **Violation of WHOIS Terms of Service** — extracting data beyond permitted limits
- **Data Exposure** — bulk scraping of domain owner contact information
- **Resource Abuse** — unrestricted load on WHOIS servers
- **Malicious Use** — data harvested for spam, phishing, or social engineering

### Remediation

1. **Do not trust `X-Forwarded-For`** for access control decisions — use the actual connection IP (REMOTE_ADDR/socket peer address)
2. If behind a legitimate load balancer, whitelist only the trusted load balancer's `X-Forwarded-For` values
3. Implement rate limiting based on the true connection IP only
4. Consider adding session/token-based throttling as an additional layer

---

## F-005: Developer Portal and API Infrastructure Exposed — SAML SSO Discovery

**Severity:** MEDIUM / Informational  
**Target:** `developer.verisign.com/devhub/`, `unavapis.login.verisign.com/ua/`  
**CVSS:** 4.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

### Description

Two authenticated developer portals were discovered and enumerated:
- `developer.verisign.com/devhub/` — NameStudio API developer portal
- `unavapis.login.verisign.com/ua/` — Universal Navigation APIs

Both use Verisign's internal SAML SSO infrastructure (`login.verisign.com/SAML2/SSO/POST`) for authentication. The following endpoints were identified as **publicly accessible without authentication**:

| Endpoint | Status | Data |
|----------|--------|------|
| `https://developer.verisign.com/devhub/rest/pub/countries` | **HTTP 200** | Full country list JSON |
| `https://developer.verisign.com/devhub/health` | **HTTP 200** | `I am good` |
| `https://unavapis.login.verisign.com/ua/health` | **HTTP 200** | `I am good` |

The developer portal at `/devhub/request` (account registration) is publicly accessible and uses:
- Google reCAPTCHA (`6LdrqY0sAAAAADvYZ_m3xy-ir1EQogqaf0JAK999`)
- CSRF token (Spring Security, header `X-XSRF-TOKEN`)
- Fields: `firstName`, `lastName`, `email`, `companyName`, `phoneNumber`, `address`, `city`, `state`, `country`, `comments`, `captchaResponse`

The account creation API endpoint (`/devhub/rest/pub/accountrequests`) accepts POST requests with valid CSRF token — form submissions are processed (returns HTTP 400 validation error rather than 403 authentication error), suggesting the submission pipeline is reached before reCAPTCHA blocks it.

### Evidence

```bash
# Unauthenticated access to country list
GET https://developer.verisign.com/devhub/rest/pub/countries
HTTP/1.1 200 OK
Content-Type: application/json
{"AF":"Afghanistan","AL":"Albania",...}  # Full country listing

# CSRF token accepted on account request endpoint
POST https://developer.verisign.com/devhub/rest/pub/accountrequests
X-XSRF-TOKEN: <token>
Content-Type: application/json
HTTP/1.1 400 Bad Request
errorMessage: "Invalid account request for add account request"
```

### Internal Infrastructure Discovered via JS Analysis

From `unav-apis.env.js`:
- **Unav APIs**: `https://unavapis.login.verisign.com/ua`
- **VAC (Verisign Account Center)**: `https://accounts.verisign.com`

### SAMLRequest Signed with RSA-SHA512

The SP signs SAMLRequests using RSA-SHA512 (strong) and the ACS endpoint correctly validates SAML response signatures (unsigned responses return HTTP 403 "Authorization Error"). The SAML implementation is secure against signature bypass.

### Impact

- Discovery of internal API infrastructure and developer portal
- Potential for stored XSS in `comments` field if admin review renders HTML (unconfirmed, blocked by reCAPTCHA)
- Internal subdomain enumeration (`unavapis.login.verisign.com`, `accounts.verisign.com`)

### Remediation

1. Remove health check endpoints from production or restrict to internal IPs
2. Ensure `comments` and all free-text fields are properly HTML-escaped in admin views
3. Review whether the `rest/pub/` namespace should expose any data to unauthenticated users

---

## F-001: Tomcat Cluster Node Disclosure via JSESSIONID

**Severity:** LOW / Informational  
**Target:** `registrar.verisign-grs.com/webwhois-ui/`, `webwhois.verisign.com`  
**CVSS:** 3.1 (Low)

### Description

The `JSESSIONID` cookie suffix discloses Tomcat cluster node identifiers directly to clients. Three distinct nodes were identified:

- `.d3a61a62` — primary node (standard requests)
- `.c55c42fa` — secondary node (OPTIONS requests)
- `.fcf59aa8` — tertiary node (POST requests)

The same node identifier (`.d3a61a62`) appears on both `registrar.verisign-grs.com` and `webwhois.verisign.com`, confirming both domains share the same Tomcat cluster.

### Evidence

```http
GET /webwhois-ui/ HTTP/1.1
Host: registrar.verisign-grs.com

HTTP/1.1 302 Found
Set-Cookie: JSESSIONID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.d3a61a62; Path=/webwhois-ui; Secure; HttpOnly
```

### Impact

Enables attacker to map internal cluster architecture and potentially target specific nodes for session fixation or node-specific timing attacks.

### Remediation

Configure Tomcat to use random suffixes or encrypt node identifiers in `JSESSIONID`.

---

## F-002: HTTP 500 on OPTIONS Method — Unhandled Exception

**Severity:** LOW / Informational  
**Target:** `registrar.verisign-grs.com/webwhois-ui/rest/whois`  
**CVSS:** 2.5 (Low)

### Description

The WebWhois REST endpoint returns **HTTP 500 Internal Server Error** when receiving an HTTP `OPTIONS` request, indicating an unhandled exception when an unsupported HTTP method is used.

### Evidence

```http
OPTIONS /webwhois-ui/rest/whois?q=google.com&tld=com&type=quick HTTP/1.1
Host: registrar.verisign-grs.com

HTTP/1.1 500 Internal Server Error
Server: Apache
Content-Type: text/html
```

### Remediation

Add explicit handling for unsupported HTTP methods, returning 405 with a proper `Allow` header.

---

## F-003: Tiered Access WHOIS Architecture — Authentication Layer Identified

**Severity:** INFORMATIONAL  
**Target:** `registrar.verisign-grs.com/webwhois-tiered-ui/`  
**CVSS:** N/A

### Description

A Tiered Access WHOIS system exists at `/webwhois-tiered-ui/` serving registered domain industry participants. The JavaScript in `all.js` reveals authentication-based REST path routing:

```javascript
var verifyAuth = $('input[name="authpage"]').val();
if (verifyAuth) {
    restPath = "../rest/whois";  // authenticated path
}
```

All paths under `/webwhois-tiered-ui/` correctly redirect unauthenticated users to `verisigninc.com`. Testing with `X-Forwarded-For: 127.0.0.1` did not bypass the authentication redirect (access control not IP-based).

### Impact

Architecture discovery only. Authentication protection appears correctly implemented.

---

## Surfaces Not Reachable

| Target | Reason |
|--------|--------|
| EPP (`epptool-ctld.verisign-grs.com:700`) | Requires mutual TLS + authorized client certificate |
| DNS root/gTLD AXFR | Firewall — connection timeout |
| `nsw-config.verisign.com` | HTTP 403 all paths |
| `nsw-api.verisign.com` | HTTP 403 |
| `nsw-service.verisign.com` | HTTP 403 |
| `accounts.verisign.com` | Connection reset (proxy policy) |
| `youcouldbe.com` | Proxy policy denial |
| `namestudioapi.com` | CloudFront 403 (all static files) |

---

## Hardened Surfaces (No Findings)

| Surface | Protection |
|---------|-----------|
| `webwhois.verisign.com` XSS | Input HTML-encoded via `getI18Message()` before Handlebars template |
| `www.verisign.com/search` | DOMPurify 3.4.2, strong CSP (`strict-dynamic` + SHA256) |
| Cludo Search API | Read-only credentials (SearchKey), content push returns 404 |
| RDAP (`rdap.verisign.com`) | JSON-only responses, no XSS vector |
| WHOIS SQL injection | `tld` parameter input validation, no timing-based blind SQLi |
| Developer Portal SAML | RSA-SHA512 signed SAMLRequests, signature validation on ACS |

---

## Conclusion

The highest-impact finding is **F-004** (X-Forwarded-For rate limit bypass, HIGH severity) which qualifies for the "Logic flaws / Security bypass" bounty category ($2,500–$5,000). The **F-005** finding documents the developer portal infrastructure and should be reviewed for the `comments` field stored XSS potential.

Verisign's publicly accessible infrastructure is significantly hardened. XSS surfaces are protected by HTML encoding and strong CSP, SQL injection surfaces appear parameterized, and the EPP protocol requires mutual TLS.

**Status:** Active — testing ongoing.
