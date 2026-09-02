# eToro Bug Bounty — Finding #2
## API Keys Hardcoded in Client-Side JavaScript Bundle

**Program:** eToro (Bugcrowd)
**Target:** `por.etoro.com` (in-scope: `*.etoro.com`)
**Severity:** P3 — Medium (Sensitive Data Exposure / Information Disclosure)
**CVSS 3.1:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Date Discovered:** 2026-09-02
**Reporter:** komeng rooket

---

## Summary

The eToro Partners Portal JavaScript bundle (`por.etoro.com`) contains hardcoded third-party service credentials including a Mixpanel analytics API key and a Google Places API key. These keys are embedded in a minified JavaScript chunk served to all visitors without authentication.

---

## Evidence

**File:** `https://por.etoro.com/chunk-FJE3VJJW.js` (publicly accessible, ~1MB)

**Extracted credentials block:**
```javascript
mixpanel:{
  activated: true,
  token: "2448f7a85e9b9a704296bbbc574a6eeb",
  apiKey: "82c497c98def92021ef7d334b601c202"
},
googlePlacesApiKey: "AIzaSyBf7jOefmuWml4YngmmPvvBb8Mw1umh588"
```

**cURL to retrieve the chunk:**
```bash
curl -s "https://por.etoro.com/chunk-FJE3VJJW.js" | \
  grep -o 'mixpanel.*googlePlacesApiKey[^}]*}'
```

---

## Credentials Breakdown

### 1. Mixpanel Project Token + API Key

| Field | Value |
|-------|-------|
| Service | Mixpanel (event analytics) |
| Project Token | `2448f7a85e9b9a704296bbbc574a6eeb` |
| API Key | `82c497c98def92021ef7d334b601c202` |

**Risk:** The Mixpanel `token` is typically designed for client-side use. However, the `apiKey` (legacy Mixpanel API Key) enables additional API access beyond basic event tracking:
- Legacy Mixpanel API Keys can be used to query the Mixpanel Data Export API to retrieve all historical event data, user profiles, and behavioral analytics
- Potential exposure of all affiliate user activity tracked via Mixpanel (page views, button clicks, funnel completions, registration events)
- An attacker can send arbitrary events to corrupt eToro's affiliate analytics data
- The `apiKey` may grant access to Mixpanel's People analytics, revealing all tracked affiliate user properties and attributes

### 2. Google Places API Key

| Field | Value |
|-------|-------|
| Service | Google Maps Platform — Places API |
| Key | `AIzaSyBf7jOefmuWml4YngmmPvvBb8Mw1umh588` |

**Testing Results:**
```
$ curl "https://maps.googleapis.com/maps/api/place/textsearch/json?query=test&key=AIzaSyBf7jOefmuWml4YngmmPvvBb8Mw1umh588"
{
  "status": "REQUEST_DENIED",
  "error_message": "API keys with referer restrictions cannot be used with this API."
}
```

**Risk:** The Google Places API key has HTTP referer restrictions applied (it can only be used from authorized domains). This mitigates server-side abuse. However, the key remains exploitable by:
- Browsers running on `por.etoro.com` (the authorized domain) — any user can abuse the quota
- Possible bypass if referer header can be spoofed in certain client contexts
- Financial impact to eToro if the Places API key quota is exceeded through abuse

---

## Impact

**Mixpanel API Key Exposure:**
- Access to eToro's Mixpanel project analytics data without authorization
- Ability to inject false analytics events, corrupting eToro's conversion tracking and funnel analysis
- Potential PII exposure if any user-identifiable properties are tracked in Mixpanel (email, name, affiliate ID)
- Competitor intelligence: access to detailed affiliate portal usage patterns

**Google Places API Key:**
- Currently mitigated by referer restrictions
- Residual risk if restrictions are removed or misconfigured in the future

---

## CVSS Breakdown

| Metric | Value | Reason |
|--------|-------|--------|
| Attack Vector | Network | Public bundle accessible globally |
| Attack Complexity | Low | Simple extract from JS file |
| Privileges Required | None | No authentication needed |
| User Interaction | None | No victim interaction required |
| Scope | Unchanged | |
| Confidentiality | Low | Analytics data potentially exposed |
| Integrity | Low | Events can be injected |
| Availability | None | |

**CVSS Score: 5.3 (Medium / P3)**

Note: If the Mixpanel API key actively grants data export access, severity upgrades to P2 (High), as affiliate behavioral data constitutes sensitive business intelligence.

---

## Remediation

1. **Mixpanel**: Rotate the API key immediately. Do not store the Mixpanel API Key in client-side bundles — it should remain server-side only. The `token` (project token) is acceptable in front-end code; the `apiKey` is not.

2. **Google Places**: The referer restriction is correct. Ensure the key is restricted to only the `Places API` within the Google Cloud Console, with no broader permissions. Regularly audit the key's usage in the Google Cloud Console.

3. **General Practice**: Use environment variable substitution at build time (never hardcode production keys in source) and conduct a secrets scan on the repository before each deployment.

---

## Timeline

- 2026-09-02: Credentials extracted from public JS bundle via passive analysis
- 2026-09-02: Reported via Bugcrowd

---

*Reported by: komeng rooket | Bugcrowd eToro Program*
