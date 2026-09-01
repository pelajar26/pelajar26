# Bugcrowd Finding #7 — API Keys Exposed in Client-Side JavaScript (comunidade.nubank.com.br)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P3 Medium (depending on scope of exposed keys)
**Target:** `comunidade.nubank.com.br` (NuCommunity powered by Bettermode)
**VRT:** Server Security Misconfiguration > Sensitive Data Exposure

---

## Summary

The `comunidade.nubank.com.br` page embeds multiple API keys and secrets in its publicly accessible JavaScript bundle. While some keys belong to the Bettermode platform (third-party), the Segment analytics write key may be scoped to Nubank's analytics workspace, enabling injection of fraudulent analytics events.

---

## Technical Evidence

**Request:**
```bash
curl -s "https://comunidade.nubank.com.br/" \
  -H "X-Correlation-Id: bc-handle"
```

**Extracted from `window.RuntimeConfigs` in the HTML response:**
```json
{
  "GQL_ENDPOINT": "https://api.bettermode.com",
  "FIREBASE_API_KEY": "AIzaSyAOg7DiR0iacQPO7jlix_6MgWe3JXhfGtg",
  "FIREBASE_VAPID_KEY": "BLxlLxenGuNYPnbQdGFuKxqCqDrMPWH_4A_dbi6pSCHBrdQs6NoTZE17ujuh90XK0kPolN_K0GHeqg6cnn8lRaM",
  "FIREBASE_AUTH_DOMAIN": "tribeplatform.firebaseapp.com",
  "FIREBASE_PROJECT_ID": "tribeplatform",
  "FIREBASE_MESSAGING_SENDER_ID": "1081893321319",
  "FIREBASE_APP_ID": "1:1081893321319:web:baed5f30cea3272be9f2c2",
  "FIREBASE_MEASUREMENT_ID": "G-VQ1KRW18TJ",
  "SEGMENT_WRITE_KEY": "rzdxGWPeatY5ndzGQpxGF1WiRjslM1sn",
  "UNSPLASH_ACCESS_KEY": "WR-Inn5J8i7V4U2lf-agxDhxySNKzKxWBOiIA4MLwU4",
  "GIPHY_API_KEY": "6kgUMFc6AkHJRRxnaF98nKsyDGzdNCZR"
}
```

---

## Risk Analysis

### Key 1: Segment Write Key — `rzdxGWPeatY5ndzGQpxGF1WiRjslM1sn`

**Risk: Medium-High (if Nubank-specific)**

Segment write keys are customer-specific per workspace. If this key is tied to Nubank's Segment workspace:
- Attacker can inject arbitrary analytics events: `POST https://api.segment.io/v1/track` with this key
- This could corrupt Nubank's analytics data pipeline
- Fake user actions (purchases, account creations, fraud signals) could be injected
- Potential to trigger automated marketing flows, fraud detection false positives, or BI data contamination

**Note:** If this key is a Bettermode shared key, impact is limited to the Bettermode analytics workspace.

### Key 2: Firebase API Key — `AIzaSyAOg7DiR0iacQPO7jlix_6MgWe3JXhfGtg`

**Risk: Medium (depends on Firebase Security Rules)**

Firebase project: `tribeplatform` (Bettermode's platform).

While Firebase API keys are technically public-facing design (unlike backend secrets), misconfigured Firebase Security Rules can allow unauthenticated data reads/writes. Standard risk areas include:
- Realtime Database: `https://tribeplatform-default-rtdb.firebaseio.com/.json`
- Firestore: collections with public read access
- Firebase Auth: account enumeration or registration abuse

**Note:** This is Bettermode's Firebase project, likely outside Nubank's direct bug bounty scope, but the exposure is through Nubank's subdomain.

### Key 3: Firebase VAPID Key

Used for Web Push Notifications. If an attacker can register a service worker on `comunidade.nubank.com.br` (via XSS), this key enables push subscription abuse.

---

## Attack Chain: Segment + Analytics Data Injection

```
Attacker reads SEGMENT_WRITE_KEY from page source
  → POSTs fake events to Segment: 
    {"writeKey":"rzdxGWPeatY5ndzGQpxGF1WiRjslM1sn",
     "userId":"victim-123",
     "event":"purchase",
     "properties":{"amount":9999.99,"product":"NuInvest"}}
  → Nubank analytics shows fraudulent user activity
  → BI/fraud models react to injected signals
  → Potential false fraud alerts or corrupted business intelligence
```

---

## Evidence Collection Method

Keys were observed directly in the HTML source returned by `GET https://comunidade.nubank.com.br/` — no authentication, no brute force, no active exploitation. The `window.RuntimeConfigs` JavaScript object is embedded in the server-rendered HTML for all visitors including unauthenticated guests.

---

## Remediation

1. **Segment Write Key**: If scoped to Nubank's workspace, rotate immediately. Use server-side analytics proxying — never expose write keys to the browser.
2. **Firebase API Key**: Verify Firebase Security Rules for the `tribeplatform` project restrict all sensitive collections to authenticated users. Ensure the key cannot be used to write arbitrary data.
3. **VAPID Key**: Acceptable to expose if push subscriptions are server-validated. Ensure subscription registration requires authenticated sessions.
4. **Platform review**: Engage Bettermode to audit what credentials they expose in the client-side bundle for all white-labeled communities.

---

## Notes

- All keys extracted via passive reading of the public HTML response
- No active exploitation of any third-party service was attempted
- Firebase project `tribeplatform` belongs to Bettermode, not directly to Nubank
- The Segment write key risk depends on whether it is scoped to Nubank's workspace
- All requests used `X-Correlation-Id: bc-handle` as required
