# Bugcrowd Finding #22 — JavaScript Source Maps Publicly Accessible on nu.com.co — Exposes Internal Codebase, Private npm Packages, Monorepo Paths, Sentry DSNs, and Base64-Encoded Staging/Production URLs

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P3 Medium — Source code structure, internal paths, and encoded sensitive URLs disclosed
**Severity (Chained):** P2 High — Decoded staging endpoints enable full staging service mapping (see Finding #23)
**VRT:** Server Security Misconfiguration > Sensitive Data Exposure
**Related:** Finding #21 (unauthenticated discovery API), Finding #23 (staging service map)

---

## Summary

All JavaScript source map files (`.js.map`) for `nu.com.co` (Nubank's Colombian website) are publicly accessible with HTTP 200, without authentication. The source maps expose:

1. **Internal monorepo project path**: `/workspace/projects/www-latam/`
2. **Private npm package names**: `@nubank/www-latam-commons`, `@nubank/nuds-web`
3. **Complete React/Next.js source code** of all public pages
4. **Two Sentry DSNs** (Org ID 13389) with secret keys
5. **Base64-encoded URLs** that decode to complete staging and production microservice endpoints

The source maps are stored in the same Amazon S3 bucket that serves the `nu.com.co` website assets, with `REDUCED_REDUNDANCY` storage class — suggesting they were unintentionally deployed alongside the production assets.

---

## Technical Evidence

### 1. Source Maps Accessibility

```bash
# All of these return HTTP 200:
curl -sI "https://nu.com.co/_next/static/chunks/pages/procesando-pago-f0df0c2005b137e47688.js.map" \
  -H "X-Correlation-Id: bc-handle"
# HTTP/2 200
# content-type: binary/octet-stream
# x-amz-storage-class: REDUCED_REDUNDANCY
# x-amz-server-side-encryption: AES256
# server: AmazonS3

curl -sI "https://nu.com.co/_next/static/chunks/pages/_app-0b151afef60edd59c69a.js.map"
# HTTP/2 200
curl -sI "https://nu.com.co/_next/static/chunks/framework.53ef11ff3b8561279010.js.map"
# HTTP/2 200
curl -sI "https://nu.com.co/_next/static/chunks/commons.89ed45dc68d2acc5be36.js.map"
# HTTP/2 200
curl -sI "https://nu.com.co/_next/static/chunks/main-ef1574baeaa9f19b2821.js.map"
# HTTP/2 200
curl -sI "https://nu.com.co/_next/static/chunks/ff815b1ff578d901ec03147a1bdeea6d9eea7aaf.6ceb4b488e4ddab39744.js.map"
# HTTP/2 200
```

**Contrast with nubank.com.br**: Source maps on `static.nubank.com.br` return HTTP 403 — correctly protected. `nu.com.co` lacks this protection.

---

### 2. Internal Project Path Disclosed

From the `_app.js` source map (`pages/_app-0b151afef60edd59c69a.js.map`):

```
Source files found:
  - webpack://_N_E//workspace/projects/www-latam/node_modules/@nubank/nuds-web/...
  - webpack://_N_E/./node_modules/@nubank/www-latam-commons/config/index.js
  - webpack://_N_E/./node_modules/@nubank/www-latam-commons/utils/environmentUtils.js
  - webpack://_N_E/./pages/_app.js
  - webpack://_N_E/./components/SiteContext/SiteContext.js
  - webpack://_N_E/./utils/error-tracking/errorTracking.js
```

**Disclosed**: Internal CI/CD workspace path `/workspace/projects/www-latam/`, monorepo structure, private npm packages `@nubank/nuds-web` (design system) and `@nubank/www-latam-commons` (shared Latin America utilities).

---

### 3. Configuration Schema Exposed — `config/index.js`

Source code from `@nubank/www-latam-commons/config/index.js` reveals the full configuration schema used by all Latin America websites:

```javascript
export const getConfig = () => ({
  locale: process.env.NEXT_PUBLIC_WWW_LOCALE,
  gtmID: process.env.NEXT_PUBLIC_WWW_GTM_ID,
  mailchimpListId: process.env.NEXT_PUBLIC_WWW_MAILCHIMP_LIST_ID,
  mailchimpWaitListId: process.env.NEXT_PUBLIC_WWW_MAILCHIMP_WAITLIST_ID,
  domain: process.env.NEXT_PUBLIC_WWW_DOMAIN,
  discoveryUrlEncodedStaging: process.env.NEXT_PUBLIC_WWW_DISCOVERY_URL_ENCODED_STAGING,
  discoveryUrlEncodedProd: process.env.NEXT_PUBLIC_WWW_DISCOVERY_URL_ENCODED_PROD,
  inviterUrlEncodedStaging: process.env.NEXT_PUBLIC_WWW_INVITER_URL_ENCODED_STAGING,
  inviterUrlEncodedProd: process.env.NEXT_PUBLIC_WWW_INVITER_URL_ENCODED_PROD,
  inviterPjUrlEncodedStaging: process.env.NEXT_PUBLIC_WWW_INVITER_PJ_URL_ENCODED_STAGING,
  inviterPjUrlEncodedProd: process.env.NEXT_PUBLIC_WWW_INVITER_PJ_URL_ENCODED_PROD,
  backendUrlEncodedStaging: process.env.NEXT_PUBLIC_WWW_BACKEND_URL_ENCODED_STAGING,
  backendUrlEncodedProd: process.env.NEXT_PUBLIC_WWW_BACKEND_URL_ENCODED_PROD,
  recaptchaSiteKey: process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY,
  sentryDnsEncodedProd: process.env.NEXT_PUBLIC_SENTRY_ENCODED_DSN_PROD,
  sentryDnsEncodedStaging: process.env.NEXT_PUBLIC_SENTRY_ENCODED_DSN_STAGING,
  recordingsUrlEncodedProd: process.env.NEXT_PUBLIC_WWW_RECORDINGS_URL_ENCODED_PROD,
  recordingsUrlEncodedStaging: process.env.NEXT_PUBLIC_WWW_RECORDINGS_URL_ENCODED_STAGING,
  goteraUrlEncodedProd: process.env.NEXT_PUBLIC_WWW_GOTERA_URL_ENCODED_PROD,
  goteraUrlEncodedStaging: process.env.NEXT_PUBLIC_WWW_GOTERA_URL_ENCODED_STAGING,
});
```

**Key disclosure**: Nubank uses base64 encoding to obfuscate URLs in environment variables, but this encoding is trivially reversible. The source code also reveals service names not previously known: `gotera`, `inviter`, `inviterPj`, `recordings`.

---

### 4. `environmentUtils.js` — URL Decoding Logic Exposed

```javascript
// From @nubank/www-latam-commons/utils/environmentUtils.js
export function getDecodedConfigStrFunction(prodStrKey, stagingStrKey) {
  return () => {
    const str64 = isProduction() ? config[prodStrKey] : config[stagingStrKey];
    return base64Decode(str64);
  };
}

export const getDiscoveryUrl = getDecodedConfigStrFunction('discoveryUrlEncodedProd', 'discoveryUrlEncodedStaging');
export const getInviterUrl = getDecodedConfigStrFunction('inviterUrlEncodedProd', 'inviterUrlEncodedStaging');
export const getBackendURL = getDecodedConfigStrFunction('backendUrlEncodedProd', 'backendUrlEncodedStaging');
export const getSentryDnsUrl = getDecodedConfigStrFunction('sentryDnsEncodedProd', 'sentryDnsEncodedStaging');
export const getRecordingsUrl = getDecodedConfigStrFunction('recordingsUrlEncodedProd', 'recordingsUrlEncodedStaging');
export const getGoteraUrl = getDecodedConfigStrFunction('goteraUrlEncodedProd', 'goteraUrlEncodedStaging');
```

---

### 5. Base64-Encoded URLs Decoded from Compiled JS Bundle

Since `NEXT_PUBLIC_*` environment variables are inlined at build time in Next.js, the actual base64-encoded values are present in the compiled JavaScript bundle. Decoding these reveals:

```
# Staging discovery endpoint:
aHR0cHM6Ly9zdGFnaW5nLWdsb2JhbC1kaXNjb3ZlcnktY2YubnUuY29tLmNvL2FwaS9kaXNjb3Zlcnk=
→ https://staging-global-discovery-cf.nu.com.co/api/discovery

# Production discovery endpoint (confirmed in Finding #21):
aHR0cHM6Ly9wcm9kLWdsb2JhbC1kaXNjb3ZlcnktY2YubnUuY29tLmNvL2FwaS9kaXNjb3Zlcnk=
→ https://prod-global-discovery-cf.nu.com.co/api/discovery

# Staging webapp proxy inviter:
aHR0cHM6Ly9zdGFnaW5nLWdsb2JhbC13ZWJhcHAtcHJveHkubnUuY29tLmNvL2FwaS9pbnZpdGVyLzpzbHVn
→ https://staging-global-webapp-proxy.nu.com.co/api/inviter/:slug

# Production webapp proxy inviter:
→ https://prod-global-webapp-proxy.nu.com.co/api/inviter/:slug

# Sentry DSN 1 (CO staging or prod):
aHR0cHM6Ly9iODlmYzljNzQwNTAzYWEwNjMyYjRmZjVjMDdhNThkN0BvMTMzODkuaW5nZXN0LnVzLnNlbnRyeS5pby80NTA3NDI2NDg4ODQ0Mjg4
→ https://b89fc9c740503aa0632b4ff5c07a58d7@o13389.ingest.us.sentry.io/4507426488844288

# Sentry DSN 2:
aHR0cHM6Ly8wY2Q2ZTExZDU5ZWUyNjY2YjhjOTI3N2U1OTg1NWYzMUBvMTMzODkuaW5nZXN0LnVzLnNlbnRyeS5pby80NTA3NDY0NTE0NDY5ODg4
→ https://0cd6e11d59ee2666b8c9277e59855f31@o13389.ingest.us.sentry.io/4507464514469888
```

---

### 6. Sentry DSN Exposure

Two Sentry DSNs are exposed, both under **Org ID 13389** (confirmed Nubank's Sentry organization from nubank.com.br HTML):

| DSN Component | Value |
|---|---|
| DSN 1 Key | `b89fc9c740503aa0632b4ff5c07a58d7` |
| DSN 1 Project | `4507426488844288` |
| DSN 2 Key | `0cd6e11d59ee2666b8c9277e59855f31` |
| DSN 2 Project | `4507464514469888` |
| Org | `o13389.ingest.us.sentry.io` |

**Impact of DSN exposure**: Sentry DSNs contain a secret project key. While Sentry DSNs are partially public (required for client-side SDKs), the specific project key (`b89fc9c740503aa0632b4ff5c07a58d7`) enables:
- Submitting fake error reports to Nubank's Sentry monitoring
- Rate-limiting/flooding Nubank's error monitoring pipeline
- Understanding Nubank's error monitoring infrastructure

More critically, the disclosed DSN keys allow an attacker to write a script that submits thousands of fake high-severity errors to Nubank's Sentry projects, creating noise that masks real security incidents or triggers false alert fatigue.

---

## Attack Chain — Source Maps Enable Staging Service Discovery

```
[Step 1] Attacker downloads source maps from nu.com.co:
  → HTTP 200 (no auth required)
  → Finds base64-encoded staging discovery URL in compiled JS

[Step 2] Decodes staging discovery URL:
  → https://staging-global-discovery-cf.nu.com.co/api/discovery

[Step 3] Accesses staging discovery endpoint (unauthenticated):
  → Returns complete staging microservice map (see Finding #23)
  → Includes staging proxy HMAC tokens for all operations

[Step 4] Tests staging services for authentication weaknesses:
  → staging-global-stevie.staging-waf.nu.com.co returns data without auth
  → staging-global-auth.nu.com.co CORS-reflects any nu.com.co origin with credentials

[Impact] Complete staging environment mapped; staging services tested for weaknesses
         before attacking equivalent production services
```

---

## Severity Assessment

| Issue | Severity | Rationale |
|-------|----------|-----------|
| Source map public access | P3 Medium (standalone) | Source code structure + internal paths disclosed |
| Base64 URL decoding | P2 High (chained) | Enables staging service discovery (Finding #23) |
| Sentry DSN exposure | P3 Medium | Enables fake error submission / alert flooding |
| Private npm package names | P4 Informational | Confirms `@nubank/www-latam-commons` private package exists |

---

## Remediation

| Issue | Fix |
|-------|-----|
| Source maps in S3 | Remove `.js.map` files from the S3 bucket serving `nu.com.co` assets, or block public access to `*.js.map` paths via CloudFront behavior rules |
| S3 bucket policy | Apply S3 bucket policy to deny GetObject on `*.map` files: `"Condition": {"StringLike": {"s3:prefix": ["*/*.map"]}}` |
| nubank.com.br model | Follow `static.nubank.com.br` which correctly returns 403 on `.js.map` requests |
| Sentry DSNs | Rotate Sentry DSN keys for projects 4507426488844288 and 4507464514469888 to invalidate leaked keys |

---

## Notes

- Source maps verified accessible via HTTP HEAD and GET with Content-Type `binary/octet-stream`
- S3 `REDUCED_REDUNDANCY` storage class on source maps suggests accidental deployment (vs. intentional)
- `nubank.com.br` source maps correctly return 403 via CloudFront — nu.com.co should match this configuration
- No actual XSS injection, code modification, or Sentry submission performed
- All analysis via passive GET/HEAD requests
