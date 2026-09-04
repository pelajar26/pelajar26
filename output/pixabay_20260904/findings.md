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
| Videos | large, medium, small, tiny | _original, _source (403) |
| Audio | Unknown - all tested patterns 403 | Unknown |
| Vectors | Served as PNG (640px, 1280px) | Original vector file (403) |

CDN correctly protects higher-resolution/original quality content. Lower-quality public versions align with Pixabay's CC0 free content model.

### API Assessment
- **Auth method:** API key in query parameter (`?key=...`)
- **CORS:** `Access-Control-Allow-Origin: *` — by design for public API
- **Rate limiting:** 100 req/60s with headers `X-RateLimit-*`
- **JSONP:** `callback` parameter available for JSONP responses (untested - no valid API key)
- **Full API Access:** Requires separate approval for `fullHDURL`, `imageURL`, `vectorURL` fields

### OAuth Configuration
- **Google OAuth:** Client ID `1090459648980-gmj09fco6ujia7eut6m5hpsv961tp14e.apps.googleusercontent.com` (public by design)
- **Facebook OAuth:** Client ID `679272853362167` (public by design)
- **Redirect endpoints:** `/accounts/auth/google/`, `/accounts/auth/facebook/`

---

## Testing Results

### No Findings Confirmed

The following attack vectors were tested but no vulnerabilities confirmed:

| Vector | Result |
|---|---|
| CDN original file access bypass | 403 on all `_original`/`_source` paths |
| CORS misconfiguration | Static `*` wildcard by design, no origin reflection |
| Open redirect via `?next=` | Blocked by Cloudflare WAF |
| SQL injection via `?order=` parameter | Blocked by Cloudflare WAF |
| XSS via search query | Blocked by Cloudflare WAF for payloads; search term reflected but appears encoded |
| Subdomain internal exposure | All sensitive subdomains connection refused / internal only |
| API JSONP callback XSS | Untestable without valid API key |
| Account enumeration via registration | Untestable (Cloudflare blocks unauthenticated POST) |
| Robots.txt sensitive path access | All disallowed paths return 403 |
| User collection IDOR | 404 for tested collection URLs (format unclear) |

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

2. **JPEG files served as `binary/octet-stream`**: CDN serves JPEG images with `Content-Type: binary/octet-stream` instead of `image/jpeg`. No direct security impact but indicates missing S3 content-type metadata.

3. **No CORS headers on CDN**: `cdn.pixabay.com` does not return CORS headers. Media files accessible directly but not cross-origin fetch.

4. **Security headers on main site**: CSP with nonce, COOP (`same-origin`), COEP (`require-corp`), CORP (`same-origin`), X-Frame-Options (`SAMEORIGIN`), Referrer-Policy (`same-origin`), Permissions-Policy all present. These are explicitly out-of-scope per VDP policy.

---

*Report generated during authorized VDP engagement per Pixabay's responsible disclosure policy.*
