# Pixabay VDP — Reconnaissance & Findings Report
**Target:** *.pixabay.com  
**Date:** 2026-09-04  
**Tester:** naqkhaie.f055@gmail.com  
**Branch:** claude/bug-bounty-capabilities-l4fryb

---

## Scope
- In-scope: `*.pixabay.com`
- Out-of-scope (per policy): noisy automated tools, rate limiting (non-OTP), low-quality content access without payment, ID enumeration without further impact, third-party providers (pagely.com, zendesk.com, mandrillapp.com)

---

## Reconnaissance Summary

### Technology Stack
| Component | Technology |
|---|---|
| Frontend | Server-rendered HTML (Python/Django pattern) |
| CDN | AWS CloudFront + S3 backend |
| WAF | Cloudflare (bot protection + WAF) |
| Auth | Session cookies + Google OAuth / Facebook OAuth |
| API | REST API at `pixabay.com/api/` with key-based auth |
| Payment | Not applicable (free CC0 content platform) |

### Subdomain Enumeration (via CT logs)
| Subdomain | Accessible | Notes |
|---|---|---|
| `pixabay.com` | Yes | Main site, Cloudflare protected |
| `cdn.pixabay.com` | Yes | AWS CloudFront + S3 CDN |
| `static.pixabay.com` | No (502/proxy blocked) | Static assets - not publicly routable |
| `admin.pixabay.com` | No (connection refused) | Admin panel - internal only |
| `db.pixabay.com` | No (connection refused) | Database - internal only |
| `db1.pixabay.com` | No (connection refused) | Database replica - internal only |
| `db2.pixabay.com` | No (connection refused) | Database replica - internal only |
| `dbase.pixabay.com` | No (connection refused) | Database - internal only |
| `munin01.pixabay.com` | No (connection refused) | Munin monitoring - internal only |
| `munin02.pixabay.com` | No (connection refused) | Munin monitoring - internal only |
| `goodies.pixabay.com` | No (proxy blocked) | Unknown purpose |
| `info.pixabay.com` | No (proxy blocked) | Unknown purpose |
| `safesearch.pixabay.com` | 403 | SafeSearch API - blocked |
| `community.pixabay.com` | DNS not found | Email community platform |
| `ablink.community.pixabay.com` | DNS not found | SendGrid email tracking |
| `mc.pixabay.com` | DNS not found | MailChimp |
| `de.pixabay.com` | DNS not found | German locale (historical) |
| `mn01-mn07.pixabay.com` | DNS not found | Media nodes |
| `rc1.pixabay.com`, `rc2.pixabay.com` | DNS not found | Release candidates |

**Finding:** Internal infrastructure subdomains (`admin`, `db`, `munin`) present in Certificate Transparency logs but not publicly accessible. No exposed admin interfaces found.

### Key Endpoints Mapped
```
# Public (no auth)
GET  /                           ← Main site
GET  /api/                       ← Image search API (requires key)
GET  /api/videos/                ← Video search API (requires key)
GET  /api/docs/                  ← API documentation
GET  /images/search/{query}/     ← Search results
GET  /videos/search/{query}/     ← Video search
GET  /photos/{slug}/             ← Individual photo page
GET  /users/{username}-{id}/     ← User profile
GET  /forum/                     ← Forum (public read)
GET  /forum/topic/{slug}/        ← Forum topics (public read)
GET  /blog/posts/{slug}/         ← Blog posts
GET  /users/search/              ← Top 100 contributors (not user search)
GET  /content-reports/           ← Content reporting form

# Restricted (no auth → 403)
GET  /images/download/           ← Download (auth required)
GET  /videos/download/           ← Download (auth required)
GET  /metrics                    ← Metrics endpoint
GET  /security-bootstrap         ← Internal bootstrap
GET  /autocomplete               ← Autocomplete
GET  /newsletter                 ← Newsletter (404)
GET  /graphql                    ← GraphQL (403)
GET  /accounts/login/            ← Login
GET  /accounts/register/         ← Registration

# Authenticated
GET  /accounts/settings/         ← Account settings
GET  /accounts/messages/         ← Direct messages
GET  /users/{username}/collections/  ← User collections
GET  /accounts/media/upload/     ← Media upload
```

### CDN Access Control Assessment
| Content Type | Public Resolution | Auth Required |
|---|---|---|
| Photos | 640px, 1280px | 1920px+ (403 on CDN) |
| Videos | large, medium, small, tiny **+ bare .mp4 (original)** | _original, _source → 404 (not 403) |
| Audio | Preview files: 403 (CDN AccessDenied — S3 bucket-level block) | Full audio files blocked; consistent with intent |
| Vectors | Served as PNG (640px, 1280px) | Original SVG/vector file (403) |

**Correction from initial report:** Video CDN does NOT return 403 for `_original`/`_source` — those variants return 404 (they don't exist as named files). The actual original uploaded file is served as `{id}.mp4` or `{id}-{variant_id}.mp4` (bare, no resolution suffix) and returns **HTTP 200** without authentication. See Finding P-001 below.

**Noteworthy inconsistency:** Audio files at `cdn.pixabay.com/audio/` correctly return HTTP 403 (S3 AccessDenied bucket-level policy), confirming that Pixabay's CDN access control policy for audio is correctly applied. This makes the analogous gap for video originals (P-001) even more notable — audio is protected, video originals are not.

### API Assessment
- **Auth method:** API key in query parameter (`?key=...`)
- **CORS:** `Access-Control-Allow-Origin: *` — by design for public API
- **Rate limiting:** 100 req/60s with headers `X-RateLimit-*`
- **JSONP:** `callback` parameter available for JSONP responses (untested - no valid API key)
- **Full API Access:** Requires separate approval for `fullHDURL`, `imageURL`, `vectorURL` fields
- **Undocumented endpoint discovered:** `GET /api/audio/` — accepts same API key format, not listed in public API docs. See Finding P-002.

### OAuth Configuration
- **Google OAuth:** Client ID `1090459648980-gmj09fco6ujia7eut6m5hpsv961tp14e.apps.googleusercontent.com` (public by design)
- **Facebook OAuth:** Client ID `679272853362167` (public by design)
- **Redirect endpoints:** `/accounts/auth/google/`, `/accounts/auth/facebook/`

---

## Testing Results

---

### P-001 — Unauthenticated Access to Original Uploaded Video Files via CDN
**Severity:** Low–Medium  
**Status:** Confirmed — verified on 5 separate videos across two naming conventions (2026-09-04 re-test)

#### Description
Pixabay stores video files on S3/CloudFront under two naming conventions. In both cases, a "maximum quality" file (the file without a `_size` suffix) is publicly accessible without authentication, even though `/videos/download/` requires a valid session (HTTP 403 without cookie).

**Naming conventions observed:**
```
# Legacy (2023–early 2024): video_id + variant_id
https://cdn.pixabay.com/video/YYYY/MM/DD/{video_id}-{variant_id}_{size}.mp4  ← transcoded
https://cdn.pixabay.com/video/YYYY/MM/DD/{video_id}-{variant_id}.mp4          ← no-suffix (original/max quality)

# Newer (mid-2024+): video_id only
https://cdn.pixabay.com/video/YYYY/MM/DD/{video_id}_{size}.mp4               ← transcoded
https://cdn.pixabay.com/video/YYYY/MM/DD/{video_id}.mp4                       ← no-suffix (original/max quality)
```

Both video_id and variant_id (for legacy naming) are visible in the public CDN URLs of any transcoded variant, which are embedded in video pages and returned by the public API.

#### Evidence

**Initial test (test video later deleted):**

| File | Content-Type | Size | last-modified | x-amz-replication | HTTP |
|---|---|---|---|---|---|
| `169249-840702546_tiny.mp4` | binary/octet-stream | 10MB | 2024-03-20 | FAILED | 200 |
| `169249-840702546_large.mp4` | binary/octet-stream | 95MB | 2024-03-20 | FAILED | 200 |
| `169249-840702546.mp4` (no-suffix) | video/mp4 | **245MB** | **2023-06-29** | COMPLETED | **200** |

**Re-test (2026-09-04) — via API key to obtain current video URLs, CDN tested without auth:**

| File | Content-Type | Size | last-modified | x-amz-replication | HTTP |
|---|---|---|---|---|---|
| `203923-922675870_tiny.mp4` | binary/octet-stream | 2.6MB | — | FAILED | 200 |
| `203923-922675870_large.mp4` | binary/octet-stream | **15.9MB** | — | FAILED | 200 |
| **`203923-922675870.mp4`** (no-suffix) | **video/mp4** | **44MB** | 2024-03-12 | FAILED | **200** |
| `153976-817104245_large.mp4` | — | — | — | — | 200 |
| **`153976-817104245.mp4`** (no-suffix) | **video/mp4** | **37MB** | — | FAILED | **200** |
| `287510_large.mp4` | video/mp4 | **94.6MB** | — | FAILED | 200 |
| **`287510.mp4`** (no-suffix) | **video/mp4** | **175MB** | 2025-06-24 | FAILED | **200** |
| `228847.mp4` (no-suffix) | video/mp4 | 162MB | — | FAILED | 200 |
| `244839.mp4` (no-suffix) | — | — | — | — | 404 |

**4 of 5 tested videos** confirm the no-suffix file is publicly accessible and significantly larger than the largest transcoded variant (1.85× – 2.8× larger).

**Extended re-test (2026-09-04) — most recent uploads (2026/09/03):**

10 videos from the latest batch were tested. 4 are still accessible with no-suffix originals significantly larger than transcoded:

| ID | `_large.mp4` (API-reported) | No-suffix actual | Ratio | HTTP |
|---|---|---|---|---|
| 374359 | 2.3MB | **12.2MB** | 5.3× | **200** |
| 374344 | 1.7MB | **12.2MB** | 7.3× | **200** |
| 374321 | 26.1MB | **113.7MB** | 4.4× | **200** |
| 374358 | 95.7MB | **203.6MB** | 2.1× | **200** |
| 374325, 374332, 374330, 374336, 374335, 374338 | — | — | — | 403 |

**Partial fix observed:** 6 of 10 most-recent videos now return 403 for the no-suffix URL (S3 AccessDenied, consistent with a bucket-level policy). This suggests Pixabay may be rolling out access control fixes for newer uploads, but the rollout is not complete — 4 of 10 videos from the same date remain exposed. Older uploads (2023–2025) tested earlier remain fully accessible.

No-suffix files are distinguishable from transcoded versions by:
- No `_size` suffix in filename
- Significantly larger file size than `_large.mp4` (2.1× – 7.3×)
- `content-type: video/mp4` (older transcoded files served as `binary/octet-stream`)

Note: `x-amz-replication-status` was `COMPLETED` on the initial test file (169249) but `FAILED` on re-test files. This may reflect a change in S3 replication config or the distinction between older and newer uploads. The access control gap is confirmed regardless.

#### Impact
- The `/videos/download/` endpoint requires authentication (HTTP 403 without session), but no-suffix CDN files are publicly accessible for the majority of existing content
- No-suffix files are 2.1× – 7.3× larger than the largest transcoded variant (`_large.mp4`), indicating higher bitrate or full-resolution original
- Original files may contain camera/device metadata (EXIF/ID3) stripped during transcoding
- iOS device string found in initial original file metadata: `y,;/iOS`
- **Partial fix in progress**: 60% of newest uploads (2026-09-03) now correctly return 403; existing library remains vulnerable

#### Attack Chain
1. Open any Pixabay video page or call `/api/videos/?key={key}` (key is publicly registered, free)
2. Extract CDN URL of any size variant: `cdn.pixabay.com/video/YYYY/MM/DD/{id}-{variant}.mp4` or `cdn.pixabay.com/video/YYYY/MM/DD/{id}_{size}.mp4`
3. Drop the `_{size}` suffix from the filename → construct no-suffix URL
4. Fetch no-suffix URL directly — returns HTTP 200 with full video content, no auth required

#### Recommendations
- Add access control on CDN for bare `.mp4` files (original uploads) matching the same policy as `_1920.jpg` images (403)
- Strip EXIF/metadata from originals before storage, or restrict originals to authenticated downloaders

---

### P-002 — Undocumented `/api/audio/` API Endpoint
**Severity:** Informational  
**Status:** Confirmed — behavior with valid key now tested (2026-09-04)

#### Description
The public Pixabay API documents two endpoints: `/api/` (images) and `/api/videos/` (videos). Testing revealed a third endpoint, `/api/audio/`, which is **not documented** in the public API docs at `pixabay.com/api/docs/`.

```
# Without API key (or invalid key):
GET https://pixabay.com/api/audio/?key=INVALID&q=test
→ [ERROR 400] Invalid or missing API key (https://pixabay.com/api/docs/).

# With a valid API key (standard/unverified account):
GET https://pixabay.com/api/audio/?key={VALID_KEY}&q=nature
→ [ERROR 403] Access denied.
```

The response changes from HTTP 400 to HTTP 403 when a valid API key is presented — confirming the endpoint validates the key and then applies a separate access-level check. This is analogous to the `fullHDURL`/`imageURL`/`vectorURL` fields in the image API, which require separate "full API access" approval.

All other untested paths (`/api/music/`, `/api/sounds/`, etc.) return HTML 404 pages, while `/api/audio/` returns the proper API JSON error format.

#### Impact
- Undocumented surface area visible only to API key holders who probe the path
- The 403 vs 400 distinction leaks that audio API access is gated by an approval tier, which is not documented
- Without approved access, audio file URLs (`audioURL`, `previewURL`) cannot be assessed

#### Recommendations
- Document `/api/audio/` in the public API docs, including the approval requirement
- Ensure rate limiting applies equally to `/api/audio/` for approved accounts

---

### Attack Vectors Tested — No Vulnerabilities Confirmed

| Vector | Result |
|---|---|
| CDN photo original file access (`_1920.jpg`) | 403 on CDN — correctly blocked |
| CDN vector original file access (`.svg`) | 403 on CDN — correctly blocked |
| Video `_original.mp4` / `_source.mp4` | 404 (variant doesn't exist as named file) |
| S3 versioning bypass (`?versionId=`) | 403 — CDN strips query params |
| S3 direct bucket access (guessed names) | 404 — correct bucket name not guessed |
| CORS misconfiguration | Static `*` wildcard by design, no origin reflection |
| Open redirect via `?next=` | Blocked by Cloudflare WAF |
| SQL injection via API parameters | Blocked by Cloudflare WAF |
| XSS in search query | Blocked by Cloudflare WAF |
| Shell injection in API key param | Blocked by Cloudflare WAF (403) |
| HTTP parameter pollution on API key | Standard 400 error — no bypass |
| GraphQL endpoint (all HTTP methods) | 403 — all methods blocked |
| Host header manipulation on CDN | 530 on `img.pixabay.com` (Cloudflare origin error) |
| Path traversal on CDN | 403 — normalized server-side |
| Subdomain internal exposure | All sensitive subdomains connection refused |
| API JSONP callback XSS | Tested with valid key — callback sanitized, parentheses stripped (`alert(1)` → `alert1`), no XSS |
| Account enumeration via registration | Untestable (Cloudflare blocks unauthenticated POST) |
| Robots.txt sensitive path access | All disallowed paths return 403 |
| User collection IDOR (unauthenticated) | 403 for all tested collection URLs |

---

## Areas Requiring Authenticated Testing

The following require a valid Pixabay account:

1. **Upload functionality** (`/accounts/media/upload/`)
   - SVG file upload → XSS potential if SVG served with script-enabled content type
   - Malicious file type bypass
   - Metadata injection (EXIF, ID3 tags)

2. **API key management**
   - IDOR: Can user A access user B's API key?
   - Can API key generation be abused?

3. **Private collections / private images** 
   - IDOR: Access other users' private collections via ID
   - Test if pre-publication images are accessible via CDN URL

4. **Forum post XSS**
   - Test allowed HTML/BBCode tags for injection
   - Test rich media embeds in forum posts

5. **Account settings CSRF**
   - Change email/password via CSRF (login/logout CSRF is OOS)

6. **IDOR in request/user IDs**
   - User IDs appear sequential (e.g., `14582128`, `1195798`)
   - Test if other users' data is accessible via ID manipulation

7. **API JSONP callback XSS**
   - With valid key, test if `callback=<script>alert(1)</script>` is reflected

8. **Download endpoint bypass**
   - With session cookie, test if higher-res content accessible without proper entitlement

---

## Notable Observations (Not Vulnerabilities)

1. **robots.txt discloses internal path names**: `/security-bootstrap`, `/metrics`, `/images/download`, `/videos/download`, `/autocomplete` — standard practice but reveals internal naming.

2. **Content-Type mismatch on CDN**: Transcoded video and JPEG files served as `binary/octet-stream` instead of `video/mp4`/`image/jpeg`. Original files correctly typed. Indicates missing S3 content-type metadata applied during transcoding pipeline.

3. **No CORS headers on CDN**: `cdn.pixabay.com` does not return CORS headers. Media files accessible directly but not cross-origin fetch.

4. **Vimeo Artax used for video transcoding**: Transcoded video files contain `Vimeo Artax Video Handler` in their moov atom metadata, revealing Pixabay uses Vimeo's (Artax) transcoding infrastructure.

5. **Analytics sends data to `api.canva.com`**: Pixabay pages load a Snowplow analytics tracker that sends data to `api.canva.com/_spi/ae/snowplow/...`, reflecting Canva's acquisition of Pixabay. App ID: `frontend`.

6. **S3 replication status patterns**: Initial testing (video 169249) showed `x-amz-replication-status: COMPLETED` on the no-suffix (original) file and `FAILED` on all transcoded variants. Re-test on 2026-09-04 across 4 additional videos shows `FAILED` on all files — both no-suffix and transcoded. Possible explanations: (a) replication config was updated/disabled since initial test, (b) the initial video 169249 was an older upload that predated the current replication setup, or (c) the `COMPLETED`/`FAILED` distinction is video-specific. The replication status is not security-relevant but is informative about S3 infrastructure changes.

7. **Security headers on main site**: CSP with nonce, COOP (`same-origin`), COEP (`require-corp`), CORP (`same-origin`), X-Frame-Options (`SAMEORIGIN`), Referrer-Policy (`same-origin`), Permissions-Policy all present. These are explicitly out-of-scope per VDP policy.

8. **Auth token stored in LocalStorage (XSS escalation vector)**: Pixabay stores a standalone Django signed authentication token in `localStorage` under the `auth.connect` key:
   ```
   connect|ssr|{user_id}:{base62_unix_timestamp}:{django_hmac_signature}
   ```
   This token is generated server-side and delivered to the frontend. Unlike `sessionid` (which is `HttpOnly` and inaccessible to JavaScript), this LocalStorage token is fully readable by any JavaScript on the `pixabay.com` origin. Confirmed via browser LocalStorage inspection (acc1 token age at test time: ~15 minutes).

   Additionally, a companion `signature` field (`ssr:{b62_timestamp}:{signature}`) is stored alongside. The `hash` field uses SHA-1, which is deprecated for cryptographic use (acceptable for non-security-critical integrity only).

   **XSS impact escalation:** If any stored XSS is discovered on Pixabay (forum, upload, comments), the attacker payload can exfiltrate:
   - `document.cookie` (session cookie if not `HttpOnly`) — limited by `SameSite=Lax`
   - `localStorage['auth'].connect` (the auth token — **no flag protects LocalStorage**)
   - Any other LocalStorage values including analytics IDs

   The `auth.connect` token's purpose (WebSocket auth, SSE auth, or internal API auth) was not fully determinable from unauthenticated external testing, but its existence in LocalStorage significantly increases the value of XSS to an attacker.

   **Not separately reportable** without confirming an exploitable XSS, but important context for severity escalation if XSS is found.

   **Extended token analysis — anonymous user tokens:** Pixabay also generates signed tokens for anonymous users visiting the login and registration pages. These tokens are stored in LocalStorage under `auth.login` and `auth.register`:
   ```
   login|ssr||en|0:{base62_unix_timestamp}:{django_hmac_signature}
   register|ssr||en|0:{base62_unix_timestamp}:{django_hmac_signature}
   ```
   Differences from the authenticated `connect` token: `user_id` field is empty (anonymous), language code (`en`) is included as a field, and a `flag` field appears (`0`). The purpose of `flag` is unknown — possible values: bot score, feature flag, or consent state. These appear to serve as page-specific anti-CSRF tokens for the login/register forms. The token lifecycle: anonymous → `{login,register}` tokens; post-login → `connect` token replaces them.

   **Potential test vectors (requires browser):**
   - Can an expired `login` token be replayed on the login form POST?
   - Does changing `flag` from `0` to `1` alter application behavior?
   - Is the `login` token validated server-side on form submission, or decorative?

9. **`is_human=1` cookie**: Pixabay sets a custom `is_human=1` cookie alongside standard auth cookies. This appears to be a server-set flag (present in authenticated sessions) that may influence application-level bot detection logic distinct from Cloudflare's own bot management. If this cookie is not cryptographically bound to the session, an attacker who can set cookies (e.g., via subdomain cookie injection) could attempt to elevate perceived trust level. Not independently testable without access to the application's backend logic.

10. **Undocumented fields in API response**: The live API response contains fields not listed in the public API docs (`pixabay.com/api/docs/`):
    - `collections` (integer): number of times the image was added to user collections
    - `noAiTraining` (bool): opt-out flag for AI training use of the image
    - `isAiGenerated` (bool): AI-generated content flag
    - `isGRated` (bool): general-audience content flag
    - `isLowQuality` (bool): quality classification flag
    - `userURL` (string): direct URL to uploader's profile (redundant with `user_id`/`user` but explicit)
    - `name` (string): appears to be a shortened/derived title

    These undocumented fields are informational (no security impact individually) but indicate the API response surface is wider than documented. The `noAiTraining` and `isAiGenerated` flags in particular represent uploader preferences and content classification that Pixabay may not intend to expose in bulk via the API.

11. **API key format reveals user_id prefix (informational)**: API keys follow the format `{user_id}-{25_hex_chars}` (e.g., acc1: `57416195-9d588bb412260f1608c29a8f5`, acc2: `57416282-30bf5dbe2c504f774e7506619`). The user_id portion is already public (visible in profile URLs), so this does not constitute information disclosure. The 25-character hex suffix provides ~83 bits of entropy — brute-force is impractical. Each account receives a unique key properly scoped to that account's session.

12. **Auth token embedded in server-rendered HTML `__BOOTSTRAP__` (extends observation 8)**: The Django auth token documented in observation 8 (localStorage) also travels in the HTTP response body as part of the `__BOOTSTRAP__` JSON object embedded in the HTML `<script>` tag. Sample structure:
    ```json
    "security": {
      "timestamp": "1788529369",
      "hash": "0560ef9d396ff49ee78f4c65712dd4b1da1e3fb1",
      "signature": "ssr:1x2UBt:351wyJAR_rZoeQZB9R1uql-hktGxfJUls-959yo2WKE",
      "auth": {
        "connect": "connect|ssr|57416282:1x2UBt:kouWKp6lXVsrIZ2sl7dYxVJvVO0Lu31eOmgI5rwKzXI"
      }
    }
    ```
    The page's client-side JS writes this to localStorage after initial render. Consequences of token-in-HTML:
    - Token is present in **proxy/CDN access logs** if logging response bodies (pixabay.com uses HTTPS so transport is encrypted, but any Pixabay-side log of response content captures the token)
    - Token is captured in browser history if the HTML is cached
    - Any HTML injection vulnerability (even non-JS) on the same origin could leak the token via `innerHTML` reads or page scraping
    - Extends XSS impact already documented: the token is available both via `localStorage.getItem('auth')` and via `document.documentElement.innerHTML` parsing
    - The `hash` field uses **SHA-1** (`0560ef9d...` — 40 hex chars), which is deprecated for cryptographic use

13. **Google API Key embedded in server-rendered HTML**: The `__BOOTSTRAP__` JSON contains a Google API key:
    ```
    "googleApiKey": "AIzaSyDdeYDZCdvVgS1WXbhM5h5IWgO5lXQvTCY"
    ```
    Google API keys embedded in frontend HTML are common for client-side Maps/Places/etc. SDKs, but they must be restricted by **HTTP Referrer** (to `*.pixabay.com/*` only) and by **API scope** (only the specific APIs the key needs). If the key lacks referrer restrictions, any third party can make API calls billed to Pixabay's Google Cloud account, potentially exhausting quotas (denial of revenue) or incurring unexpected charges.
    
    The key itself is discoverable by anyone viewing Pixabay's page source. The risk depends entirely on what restrictions are set in the Google Cloud Console — which cannot be verified from outside. This is worth noting to the Pixabay team to confirm the key is restricted.

    **Recommended check:** In Google Cloud Console → APIs & Services → Credentials, verify the key has:
    - Application restrictions: HTTP referrers, limited to `*.pixabay.com/*`
    - API restrictions: limited to only the Google APIs actually used on the frontend

14. **Facebook Client Token embedded in server-rendered HTML**: The `__BOOTSTRAP__` JSON contains:
    ```
    "facebookClientToken": "8f7f83a8549c06add59404f3b92a0c27"
    ```
    Facebook Client Tokens are separate from App Secrets and are intended for use in mobile/client-side SDKs. They are less sensitive than App Secrets but can be used to make authenticated calls to Facebook's API on behalf of Pixabay's application (e.g., `/{app-id}/activities` endpoint for App Events). If not scoped correctly, third parties could:
    - Log fake App Events against Pixabay's Facebook analytics
    - Use the token to retrieve app-level public Facebook Graph data under Pixabay's identity
    
    Unlike API keys, Client Tokens cannot be restricted to specific HTTP referrers. Informational — embedded in client-side code per Facebook's documented pattern, but worth flagging to confirm the associated Facebook App's permission scope is minimal.

15. **Bot score (68) exposed in frontend `__BOOTSTRAP__`**: The server embeds Pixabay's own bot detection score for the current request directly in the rendered HTML:
    ```json
    "analyticsContext": {"bot_score": 68, "verified_bot": false}
    ```
    A score of 68 on the acc2 profile page fetch (from a server IP with no prior history, no Cloudflare clearance cookie) indicates the system considers this request moderately bot-like. The exposure of this score to the frontend means:
    - A motivated attacker can **self-calibrate** their requests in real time by observing score changes — requesting pages, adjusting headers/timing/behavior, and repeating until they achieve a low score
    - The scoring threshold for triggering CAPTCHA or blocking is implicitly revealed (scores below ~68 from this IP went unchallenged; score 68 did not trigger a challenge for the profile page)
    - This provides an oracle for tuning automated scraping or account creation bots
    
    Informational — the score is used for analytics/fingerprinting rather than hard gating based on this test, but the feedback loop it creates weakens bot-detection posture.

16. **Security header inconsistencies between pages (profile page vs. main site)**:
    Comparing HTTP response headers between the main site and the profile page (`/users/{username}-{id}/`) reveals inconsistencies:

    | Header | Main site | Profile page | Note |
    |---|---|---|---|
    | `HSTS max-age` | — | `3600` (1 hour) | Very short; HSTS recommended minimum is 1 year (31536000s) |
    | `X-Frame-Options` | `SAMEORIGIN` | `DENY` | More restrictive on profile — possible misconfiguration or inconsistency |
    | `Cross-Origin-Opener-Policy` | `same-origin` | `same-origin-allow-popups` | Weaker on profile page; `allow-popups` permits opener access from popups |
    | `Cross-Origin-Embedder-Policy` | `require-corp` | *(absent)* | Missing on profile page — COOP/COEP pair broken |
    | `Cross-Origin-Resource-Policy` | `same-origin` | *(absent)* | Missing on profile page |
    | `Referrer-Policy` | `same-origin` | `strict-origin-when-cross-origin` *(duplicated)* | Different policy AND sent as two identical headers |
    | `Content-Security-Policy` | Full policy | `frame-ancestors 'none'` only | Profile CSP far more permissive |
    | `Content-Security-Policy-Report-Only` | *(absent)* | `frame-ancestors 'none'` | Report-only CSP mirrors enforcement CSP — redundant |

    The HSTS `max-age=3600` is notably weak — a 1-hour HSTS window means the protection against SSL stripping resets hourly; clients that haven't visited Pixabay in the last hour are not protected. Industry standard is `max-age=31536000; includeSubDomains; preload`.
    
    The `COOP: same-origin-allow-popups` on the profile page means a popup window opened from the profile page could still retain `window.opener` access, reducing isolation compared to `same-origin`. When COEP is simultaneously absent, the COOP/COEP pair required for `SharedArrayBuffer` and cross-origin isolation is incomplete on profile pages.
    
    Per VDP policy, standalone security header findings are out of scope. Documented here for completeness and as context for any XSS escalation.

17. **Search filter `user_id:` syntax discoverable via source (content enumeration)**: The user profile page search form action contains:
    ```
    /images/search/user_id%3a{user_id}%20/
    ```
    This reveals that `user_id:{id}` is a valid search filter in Pixabay's search URL syntax (URL-encoded colon → `%3a`). Combined with the sequential, public user IDs visible in profile URLs, this allows enumeration of all content uploaded by any specific user — including content that may not be prominently surfaced via the user's public profile. Informational — the user IDs are already public and the search is returning already-public images, but the filter syntax was previously undocumented.

---

*Report generated during authorized VDP engagement per Pixabay's responsible disclosure policy.*
