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
**Status:** Confirmed (original test video deleted; vulnerability pattern independently confirmed across 3 videos at time of testing — see re-test note below)

#### Description
Pixabay stores original uploaded video files on S3/CloudFront alongside transcoded variants (`_tiny`, `_small`, `_medium`, `_large`). The transcoded variants are intentionally public. However, the **original uploaded file** is also publicly accessible via a predictable URL pattern — without authentication.

The naming convention for original files is:
```
https://cdn.pixabay.com/video/YYYY/MM/DD/{video_id}-{variant_id}.mp4
```
where `{video_id}` and `{variant_id}` are visible in the transcoded file URLs.

#### Evidence

| File | Content-Type | Size | last-modified | x-amz-replication | HTTP |
|---|---|---|---|---|---|
| `169249-840702546_tiny.mp4` | binary/octet-stream | 10MB | 2024-03-20 | FAILED | 200 |
| `169249-840702546_large.mp4` | binary/octet-stream | 95MB | 2024-03-20 | FAILED | 200 |
| `169249-840702546.mp4` (original) | video/mp4 | **245MB** | **2023-06-29** | COMPLETED | **200** |

Confirmed on 3 different videos. The original file is distinguishable from transcoded versions by:
- Older `last-modified` timestamp (upload date, pre-dates transcoding)
- Larger or significantly different file size
- Correct `content-type: video/mp4` (transcoded serve as `binary/octet-stream`)
- `x-amz-replication-status: COMPLETED` (vs `FAILED` on transcoded)
- No multipart-upload ETag indicator (no `-N` suffix on ETag)

#### Impact
- The `/videos/download/` endpoint requires authentication (HTTP 403 without session), but the original file on CDN is accessible without any authentication
- For video 169249, the original (245MB) is **2.6× larger** than `_large.mp4` (95MB), suggesting higher quality or different encoding
- Original files may contain camera/device metadata (EXIF/ID3) that was stripped during transcoding
- iOS device string found in sample original file metadata: `y,;/iOS`

#### Attack Chain for Higher Severity
1. Find any video page → extract `{video_id}-{variant_id}` from public `_tiny.mp4` URL
2. Construct original URL: `cdn.pixabay.com/video/YYYY/MM/DD/{ID}.mp4`
3. Download original without login, bypassing `/videos/download/` auth gate

#### Re-test Note (2026-09-04)
Video 169249 (`169249-840702546.mp4`) returns HTTP 404 on re-test — the video was deleted from Pixabay after initial testing, causing both original and transcoded variants to 404. This is consistent with content deletion (S3 object removal), not with a server-side fix for the vulnerability. The CDN access control pattern for audio files remains HTTP 403 (bucket-level policy), indicating no global policy change for video originals has been applied.

**Pending:** Confirmation with a second valid video ID to verify the vulnerability persists for videos still on the platform.

#### Recommendations
- Add access control on CDN for bare `.mp4` files (original uploads) matching the same policy as `_1920.jpg` images (403)
- Strip EXIF/metadata from originals before storage, or restrict originals to authenticated downloaders

---

### P-002 — Undocumented `/api/audio/` API Endpoint
**Severity:** Informational  
**Status:** Confirmed (existence only; behavior with valid key untested)

#### Description
The public Pixabay API documents two endpoints: `/api/` (images) and `/api/videos/` (videos). Testing revealed a third endpoint, `/api/audio/`, which is **not documented** in the public API docs at `pixabay.com/api/docs/`.

```
GET https://pixabay.com/api/audio/?key=INVALID&q=test
→ [ERROR 400] Invalid or missing API key (https://pixabay.com/api/docs/).
```

The endpoint accepts standard API key format and consistent error messages. All other untested paths (`/api/music/`, `/api/sounds/`, etc.) return HTML 404 pages, while `/api/audio/` returns the proper API JSON error format.

#### Impact
- Undocumented surface area for API key holders
- Without a valid API key, full behavior (response structure, rate limits, available fields) cannot be assessed
- May expose audio file URLs (`audioURL`, `previewURL`) analogous to `fullHDURL` for videos

#### Recommendations
- Document `/api/audio/` in the public API docs if intended for external use
- Ensure rate limiting and access control apply equally to `/api/audio/`

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
| API JSONP callback XSS | Untestable without valid API key |
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

6. **S3 replication failure on all transcoded videos**: `x-amz-replication-status: FAILED` on all tested transcoded video files; only original files show `COMPLETED`. This suggests cross-region replication is configured for the S3 bucket but the transcoding pipeline is not writing files correctly for replication.

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

9. **`is_human=1` cookie**: Pixabay sets a custom `is_human=1` cookie alongside standard auth cookies. This appears to be a server-set flag (present in authenticated sessions) that may influence application-level bot detection logic distinct from Cloudflare's own bot management. If this cookie is not cryptographically bound to the session, an attacker who can set cookies (e.g., via subdomain cookie injection) could attempt to elevate perceived trust level. Not independently testable without access to the application's backend logic.

---

*Report generated during authorized VDP engagement per Pixabay's responsible disclosure policy.*
