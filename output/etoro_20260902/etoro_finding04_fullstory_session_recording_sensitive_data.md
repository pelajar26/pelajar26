# Finding #04 — Third-Party Session Recording Leaks Sensitive Affiliate Financial Data

**Program:** eToro Bug Bounty (Bugcrowd)  
**Date Found:** 2026-09-02  
**Severity:** P2 HIGH (CVSS 7.1)  
**CVSS Vector:** AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N  
**CWE:** CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor) + CWE-1021 (Improper Restriction of Rendered UI Layers)

---

## Summary

The eToro Partners Portal (`por.etoro.com`) injects the **FullStory session recording script** for 50% of authenticated affiliate partners — including during KYP (Know Your Partner) onboarding where highly sensitive financial data (IBAN, bank account details, passport numbers, tax IDs) is entered. The portal is served from **Amazon S3 with no `Content-Security-Policy` header**, giving the third-party FullStory script unrestricted access to the full DOM. Without explicit input masking configuration, FullStory's recording may capture unredacted financial data and transmit it to `fullstory.com` servers outside eToro's control.

---

## Affected Asset

- **Host:** `por.etoro.com` (Amazon S3 Static Website Hosting)
- **Technology:** Angular 17 SPA, FullStory browser SDK v1.2.0
- **Scope:** `*.etoro.com` ✓

---

## Technical Details

### FullStory Session Recording Integration

Extracted from `chunk-4XHNSJCO.js` (served at `https://por.etoro.com/`):

```javascript
setUser(t) {
  let e = Number(localStorage.getItem(this.localStorageKey));
  if (!e) {
    let i = Math.floor(Math.random() * 2) + 1;  // Random 1 or 2
    e = i;
    localStorage.setItem(this.localStorageKey, i.toString())
  }
  this.isActive = e == 1;   // 50% probability of activation
  this.isActive && !this.isInitialized && (
    this.injectSnippetCode(),
    this.identifyUser(t),
    this.isInitialized = !0
  )
}

injectSnippetCode() {
  window._fs_debug = false,
  window._fs_host = "fullstory.com",
  window._fs_script = "edge.fullstory.com/s/fs.js",
  window._fs_org = "cL5",              // eToro's FullStory organisation ID
  window._fs_namespace = "FS"
  // ... FullStory browser snippet injected dynamically
}

identifyUser(t) {
  window.FS.identify(t.id, {})  // Affiliate partner's internal ID sent to FullStory
}
```

**Key observations:**

| Property | Value |
|----------|-------|
| FullStory Org ID | `cL5` |
| Activation rate | 50% of authenticated users (random 1 or 2) |
| SDK version | `1.2.0` (older browser snippet API) |
| User identification | Partner's internal eToro ID sent to FullStory |
| Input masking config | **Not present in source code** |

### Missing Content-Security-Policy

`por.etoro.com` is served directly from Amazon S3 with **no security headers**:

```
HTTP/1.1 200 OK
x-amz-id-2: dyzzBMxPMWQGHmr12Ijw2yeQmzgMJh2KMSaDrU+...
x-amz-request-id: 1SSZ1ZTH4ZNAN83D
x-amz-server-side-encryption: AES256
Content-Type: text/html
Server: AmazonS3
```

**Headers completely absent:**

| Header | Present |
|--------|---------|
| `Content-Security-Policy` | ❌ Missing |
| `Strict-Transport-Security` | ❌ Missing |
| `X-Content-Type-Options` | ❌ Missing |
| `Referrer-Policy` | ❌ Missing |
| `Permissions-Policy` | ❌ Missing |
| `X-Frame-Options` | ❌ Missing |

Without a CSP, the dynamically-injected FullStory script (`edge.fullstory.com/s/fs.js`) has unrestricted access to the entire page DOM, including all rendered content and all form input values.

### Sensitive Data Entered During Session

The KYP (Know Your Partner) onboarding form — filled out by affiliate partners while logged in — collects:

Extracted from `chunk-UCISFNOZ.js`:

```javascript
je = class {
  paymentMethod = new Eo;
  paymentCurrency = new xo;
  beneficiaryName = "";
  ibanNumber = "";          // Full IBAN number
  bankName = "";
  bankCountryId = new le;
  accountNumber = "";
  swiftCode = "";
  sortCode = "";
  routingNumber = "";
  isIntermediaryBank = new ue;
  intermediaryBankName = "";
  intermediaryAccountNumber = "";
  intermediarySwiftCode = "";
};
```

Additional sensitive data collected in the same session:
- Passport/national ID uploads (base64-encoded images rendered in the DOM)
- Tax ID (TIN) numbers
- Date of birth, full legal name, address
- W-9 / W-8 US tax forms

All of this is entered while the user is authenticated and potentially in a FullStory-recorded session.

---

## Attack Scenario

### Scenario: Sensitive Financial Data Captured by Third Party

1. An affiliate partner (`affiliate_id=12345`) logs into `por.etoro.com`
2. The Angular app rolls a random value — if `1`, FullStory is activated for this session
3. `FS.identify(12345, {})` ties the recording to the partner's ID
4. The partner navigates to the KYP form to complete onboarding
5. Partner enters: `ibanNumber = "GB29NWBK60161331926819"`, bank name, SWIFT code
6. Without input masking config, FullStory captures keystrokes and form values
7. This data is transmitted to `fullstory.com` servers (outside eToro's infrastructure)
8. Any person with access to eToro's FullStory account (`org: cL5`) can replay the session and read the unredacted IBAN/banking data

### FullStory SDK Version Risk

FullStory's SDK version `1.2.0` (the older "browser snippet" approach) predates the 2023 introduction of the default "Privacy by Default" mode in their newer SDK. Older integrations using the legacy snippet may record all input values unless `_fs_settings.privacy.defaultInputMode = "masked"` is explicitly set — which is not present in the source.

---

## Evidence

### Source Code — FullStory injection in chunk-4XHNSJCO.js

```
GET https://por.etoro.com/chunk-4XHNSJCO.js HTTP/1.1
→ 200 OK (72,358 bytes, Amazon S3)
```

Contains:
- `window._fs_org = "cL5"` (eToro FullStory organisation)
- `window._fs_script = "edge.fullstory.com/s/fs.js"` (third-party script)
- Random 50% activation: `Math.floor(Math.random() * 2) + 1`
- No `_fs_settings.privacy` or `FS.consent()` configuration

### Security Headers Verification

```
HEAD https://por.etoro.com/index.html
→ HTTP/1.1 200 OK
   Server: AmazonS3
   Content-Type: text/html
   [no Content-Security-Policy]
   [no Strict-Transport-Security]
   [no X-Content-Type-Options]
```

---

## Root Cause

1. **S3-hosted SPA without security headers**: Amazon S3 Static Website Hosting does not add security headers by default. Without a CDN (CloudFront) in front of the S3 bucket, there is no mechanism to inject CSP or other response headers.

2. **Third-party session recorder without privacy controls**: The FullStory SDK is injected using the legacy snippet (v1.2.0) without any explicit `privacy.defaultInputMode` setting or field-level masking annotations on sensitive inputs.

3. **No CSP to restrict third-party scripts**: Without CSP, there is no runtime enforcement to prevent third-party scripts from accessing the DOM or exfiltrating data.

---

## Remediation

1. **Deploy CloudFront in front of S3**: Add an AWS CloudFront distribution in front of the S3 bucket. Use CloudFront Response Headers Policies to add `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `Referrer-Policy` headers.

2. **Configure CSP to restrict FullStory**: Limit what scripts can load:
   ```
   Content-Security-Policy: script-src 'self' edge.fullstory.com; connect-src 'self' rs.fullstory.com ...
   ```

3. **Mask sensitive inputs in FullStory**: Add FullStory privacy attributes to all sensitive form fields:
   ```html
   <!-- FullStory masking: exclude IBAN, bank, passport fields from recording -->
   <input type="text" fs-exclude data-private [(ngModel)]="ibanNumber">
   ```
   Or configure SDK-level default masking:
   ```javascript
   window._fs_settings = { privacy: { defaultInputMode: 'masked' } };
   ```

4. **Review FullStory data retention**: Audit the FullStory account (`org: cL5`) to determine whether session recordings contain unmasked financial data, and purge any recordings that do.

5. **Consider whether session recording is appropriate** on pages where regulated financial data (IBAN, tax IDs) is collected. GDPR Article 25 (Privacy by Design) may require explicit consent and data minimisation for third-party recording on financial data entry screens.

---

## References

- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- FullStory Privacy Controls: https://help.fullstory.com/hc/en-us/articles/360020623574-Controlling-What-FullStory-Captures
- OWASP: Third-Party JavaScript Management
- GDPR Article 25: Data Protection by Design and by Default
- AWS CloudFront: Adding Security Headers with Response Headers Policies
