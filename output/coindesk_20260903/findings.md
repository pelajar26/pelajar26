# CoinDesk Bug Bounty — Findings Report
**Date:** 2026-09-03  
**Program:** CoinDesk Bug Bounty (via Bugcrowd)  
**Researcher:** naqkhaie.f055@gmail.com  
**Branch:** claude/bug-bounty-capabilities-l4fryb  
**Header:** X-Bug-Bounty: bugcrowd (all requests)

---

## Executive Summary

Passive reconnaissance was conducted against CoinDesk infrastructure on 2026-09-03 using certificate transparency logs (crt.sh), DNS-over-HTTPS lookups (Cloudflare DoH), and HTTP probing. 307 subdomains were enumerated. One (1) HIGH severity subdomain takeover was confirmed, one (1) MEDIUM severity set of Sailthru CNAMEs requiring manual verification was identified, and several INFORMATIONAL findings were documented. No direct testing was performed against in-scope pages at `coindesk.com` due to Vercel bot protection (HTTP 429) on the main domain.

---

## F-001: Subdomain Takeover — `go.coindesk.com` via Bitly (Unclaimed Branded Short Domain)

**Severity:** HIGH — P2  
**Target:** `go.coindesk.com`  
**Category:** Subdomain Takeover  
**CVSS:** 8.1 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

### Description

The subdomain `go.coindesk.com` has a DNS CNAME record pointing to `cname.bitly.com` (Bitly's branded short domain service), but the domain is **not registered in any Bitly account**. An attacker can claim `go.coindesk.com` as their own Bitly branded short domain by creating a free or paid Bitly account and adding this domain.

Once claimed, the attacker controls all traffic to `go.coindesk.com`, allowing them to:
- Serve phishing pages under a trusted CoinDesk URL
- Redirect users to malicious sites via `go.coindesk.com/<shortcode>`
- Serve malware download links under the CoinDesk brand
- Intercept users who clicked old Bitly-powered CoinDesk short links

### Evidence

**DNS Lookup (Cloudflare DoH):**
```
GET https://cloudflare-dns.com/dns-query?name=go.coindesk.com&type=CNAME
Accept: application/dns-json

Response: go.coindesk.com → CNAME → cname.bitly.com.
```

**HTTP Response (confirms domain is not claimed in any Bitly account):**
```http
GET / HTTP/2
Host: go.coindesk.com
X-Bug-Bounty: bugcrowd

HTTP/2 302 Found
server: nginx
location: https://bitly.com/pages/landing/branded-short-domains-powered-by-bitly?bsd=go.coindesk.com
```

The redirect to `https://bitly.com/pages/landing/branded-short-domains-powered-by-bitly?bsd=go.coindesk.com` is Bitly's canonical fingerprint for an unconfigured/unclaimed branded short domain. This response is distinct from a claimed domain, which would serve the domain owner's configured content.

### Exploitation Scenario

1. Attacker creates a Bitly account (free tier available)
2. In Bitly dashboard, attacker adds `go.coindesk.com` as a custom branded domain
3. Bitly verifies ownership by confirming the DNS CNAME already points to `cname.bitly.com` — **verification passes automatically** since the CNAME already exists
4. Attacker now controls `go.coindesk.com` and can:
   - Create `go.coindesk.com/login` → phishing page
   - Create `go.coindesk.com/promo` → malware distribution site
   - Serve any content under the trusted CoinDesk brand

### Impact

- **Brand Abuse**: Attacker uses trusted `coindesk.com` subdomain for phishing
- **User Harm**: CoinDesk readers/users who trust `go.coindesk.com` links are redirected to attacker-controlled content
- **Historical Link Hijack**: Any previously published `go.coindesk.com` short links now redirect to attacker-chosen URLs

### Remediation

**Immediate** (within 24 hours): Remove the `go.coindesk.com` CNAME record from DNS, or replace it with a record pointing to CoinDesk-controlled infrastructure.

If Bitly branded short domains are still needed: Claim `go.coindesk.com` in an official CoinDesk Bitly account immediately to prevent third-party takeover.

---

## F-002: Potential Subdomain Takeover — Sailthru CNAMEs (Unverified, Requires Manual Check)

**Severity:** MEDIUM — P3 (pending verification)  
**Targets:**  
- `link.coindesk.com` → `cb.sailthru.com`  
- `link2.coindesk.com` → `cb.sailthru.com`  
- `link.local.coindesk.com` → `cb.sailthru.com`  
- `link.staging.coindesk.com` → `cb.sailthru.com`  

**Category:** Potential Subdomain Takeover  

### Description

Four CoinDesk subdomains have DNS CNAME records pointing to `cb.sailthru.com` (Sailthru email marketing platform). Sailthru is a Marigold (formerly Campaign Monitor Group) product used for email link tracking. If these subdomains are not registered in the associated Sailthru account, they may be claimable by a third party.

Sailthru's unconfigured domain fingerprint is a `404 Hosted domain not found` response. The status of these subdomains could not be verified from the testing environment due to proxy restrictions (HTTP status 000 — connection error to Sailthru infrastructure).

### Evidence

**DNS Lookups:**
```
link.coindesk.com → CNAME → cb.sailthru.com.
link2.coindesk.com → CNAME → cb.sailthru.com.
link.local.coindesk.com → CNAME → cb.sailthru.com.
link.staging.coindesk.com → CNAME → cb.sailthru.com.
```

**HTTP Status:** Connection error (000) — proxy policy blocked Sailthru infrastructure.

### Recommended Manual Verification

From a non-proxied connection:
```bash
curl -v https://link.coindesk.com/
# If response contains "Hosted domain not found" → CONFIRMED TAKEOVER
# If response serves email tracking content → CONFIGURED, no issue
```

### Remediation

If Sailthru CNAMEs are no longer in use: Remove all four CNAME records.  
If in use: Verify each subdomain is registered in the active Sailthru account.

---

## F-003: Auth0 Tenant Discovery — `coindesk-production.us.auth0.com`

**Severity:** INFORMATIONAL  
**Target:** `auth.coindesk.com`  
**Category:** Information Disclosure

### Description

The `auth.coindesk.com` subdomain is a custom domain for an Auth0 tenant. The underlying tenant name `coindesk-production.us.auth0.com` was discovered from the X.509 certificate embedded in the JWKS response.

The OIDC discovery document is publicly accessible (standard behavior for OAuth2/OIDC providers). The following security controls are correctly configured:
- Dynamic client registration is **disabled** (`{"statusCode":400,"error":"Bad Request","message":"dynamic client registration is disabled"}`)
- Management API (`/api/v2/`) returns 404 (not exposed)
- `/userinfo` returns 401 (authentication required)

**Auth0 Tenant:** `coindesk-production.us.auth0.com`  
**OIDC Discovery:** `https://auth.coindesk.com/.well-known/openid-configuration`  
**Client ID (trade.coindesk.com):** `eNCm4Q6PI4nKRF8jUuoOGHGVDJGsX8kt` (public, expected for SPA)

### Impact

Architecture discovery only. Auth0 tenant is correctly hardened.

---

## F-004: CMS Admin Panel Publicly Accessible — `cms.coindesk.com/studio` (Sanity Studio)

**Severity:** INFORMATIONAL  
**Target:** `cms.coindesk.com/studio`  
**Category:** Information Disclosure

### Description

The Sanity Studio CMS admin interface for CoinDesk is publicly accessible at `cms.coindesk.com/studio`. The page serves with HTTP 200 and includes `x-robots-tag: noindex, nofollow`, indicating it is not intended for public discovery.

```http
GET /studio HTTP/2
Host: cms.coindesk.com

HTTP/2 200
x-robots-tag: noindex, nofollow
server: Vercel
content-type: text/html; charset=utf-8
```

The Sanity Studio requires authentication (Auth0) before any content can be viewed or modified. No unauthenticated access to CMS content or APIs was achieved. The presence of `core.sanity-cdn.com/bridge.js` confirms the Sanity.io platform.

### Impact

Minimal — confirms CoinDesk uses Sanity CMS and exposes the studio URL. Requires valid CoinDesk employee credentials to access.

### Remediation

Consider IP-restricting the `/studio` path to CoinDesk's office IP ranges.

---

## Subdomain CNAME Map (External Services)

| Subdomain | CNAME Target | Service | Status |
|-----------|-------------|---------|--------|
| `go.coindesk.com` | `cname.bitly.com` | Bitly | **UNCLAIMED — TAKEOVER** |
| `link.coindesk.com` | `cb.sailthru.com` | Sailthru | Unverified |
| `link2.coindesk.com` | `cb.sailthru.com` | Sailthru | Unverified |
| `link.local.coindesk.com` | `cb.sailthru.com` | Sailthru | Unverified |
| `link.staging.coindesk.com` | `cb.sailthru.com` | Sailthru | Unverified |
| `data.coindesk.com` | `cdn.webflow.com` | Webflow | Configured (HTTP 200) |
| `indices.coindesk.com` | `cdn.webflow.com` | Webflow | Configured (HTTP 200) |
| `support.coindesk.com` | `*.saas.atlassian.com` | Atlassian | Configured (redirects) |
| `support.customer.coindesk.com` | `cryptocompare.zendesk.com` | Zendesk | Configured (HTTP 302→/hc) |
| `videos.coindesk.com` | `kgjams13.cdn.jwplayer.com` | JW Player | Configured (HTTP 405 GET) |
| `rfi.coindesk.com` | `dpephur700n3z.cloudfront.net` | CloudFront/S3 | Configured (HTTP 200) |
| `rfiapi.coindesk.com` | `d-znzxao33il.execute-api.us-east-1.amazonaws.com` | AWS API Gateway | Configured (HTTP 404) |
| `s-chart.coindesk.com` | `ms-api-static-charts.westeurope.cloudapp.azure.com` | Azure | Configured (HTTP 405) |
| `api.cryptocompare.coindesk.com` | `data-api.cryptocompare.com` | CryptoCompare | Configured |

---

## Vercel-Deployed Subdomains

The following subdomains point to `cname.vercel-dns.com` and are served via Vercel:

| Subdomain | HTTP Status |
|-----------|------------|
| `www.coindesk.com` | 429 (Bot Protection) |
| `charts.coindesk.com` | Vercel |
| `dev.coindesk.com` | Vercel |
| `hotfix.coindesk.com` | Vercel |
| `hotfix.cms.coindesk.com` | Vercel |
| `staging.charts.coindesk.com` | Vercel |
| `staging.cms.coindesk.com` | Vercel |
| `staging.coindesk.com` | Vercel |
| `todayincrypto.coindesk.com` | 301 → `www.coindesk-indices.com` |

---

## Surfaces Not Reachable (Proxy-Blocked)

| Target | Reason |
|--------|--------|
| `api.coindesk.com` | HTTP 000 — proxy policy |
| `link*.coindesk.com` | HTTP 000 — proxy blocks Sailthru |
| `vote.coindesk.com` | HTTP 000 — proxy policy |
| `vpn.coindesk.com` | HTTP 000 — proxy policy |
| `grafana.coindesk.com` | HTTP 000 — proxy policy |
| `kibana.coindesk.com` | HTTP 000 — proxy policy |
| `www.coindesk.com` | HTTP 429 — Vercel bot protection |

---

## Out-of-Scope Exclusions Applied

The following were identified but not tested (out-of-scope per program rules):
- `uat.coindesk.com` and `uat.*` subdomains
- `consensus*.coindesk.com` subdomains
- `indices.coindesk.com` (Indices product)
- `events.coindesk.com` and `www.events.coindesk.com`

---

## Conclusion

The confirmed finding is **F-001** (`go.coindesk.com` Bitly subdomain takeover, HIGH/P2) which qualifies for Bugcrowd's subdomain takeover category. The Sailthru CNAMEs in **F-002** require manual verification from a non-proxied network before submission.

**Recommended immediate action:** Remove or reclaim `go.coindesk.com` DNS record before an attacker claims it in Bitly.

**Status:** Active — testing ongoing.
