# Bugcrowd Finding #10 — WordPress Internal Domain Exposure via Next.js Data Endpoint

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P4 Low / P3 Medium (information disclosure — internal hostname + WordPress metadata)
**Target:** `blog.nubank.com.br`
**VRT:** Server Security Misconfiguration > Information Exposure

---

## Summary

`blog.nubank.com.br` uses Next.js as a frontend rendering layer over a headless WordPress instance. The internal WordPress backend domain (`backend.blog.nubank.com.br`) is exposed in the public Next.js data endpoint (`/_next/data/[buildId]/index.json`), leaking internal WordPress post metadata including:

1. **Internal backend domain:** `https://backend.blog.nubank.com.br` — a domain not intended for public access
2. **WordPress post author IDs:** Internal numeric author IDs (e.g., `post_author: 4`, `post_author: 193`, etc.)
3. **Internal GUIDs:** WordPress internal post GUIDs referencing `backend.blog.nubank.com.br`
4. **WordPress build metadata:** Internal post IDs, modification timestamps in UTC, post status, ping status

---

## Technical Evidence

### Next.js Build ID Discovery

```bash
curl -sI "https://blog.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
# x-next-cache: MISS header reveals Next.js
# buildId discoverable from __NEXT_DATA__ script tag
```

**Build ID:** `Tsb4YXGizZXDhktmmYnNO`

### Internal Data Exposure

```bash
curl -s "https://blog.nubank.com.br/_next/data/Tsb4YXGizZXDhktmmYnNO/index.json" \
  -H "X-Correlation-Id: bc-handle"
```

**Response (excerpt):**
```json
{
  "pageProps": {
    "footer": [
      {
        "ID": 503,
        "post_author": "4",
        "post_date_gmt": "2018-11-07 17:30:58",
        "post_status": "publish",
        "post_name": "explore",
        "post_modified_gmt": "2026-07-24 19:54:36",
        "guid": "https://backend.blog.nubank.com.br/?p=503",
        "post_type": "nav_menu_item"
      },
      {
        "ID": 143611,
        "post_author": "193",
        "post_date_gmt": "2025-06-10 13:23:04",
        "guid": "https://backend.blog.nubank.com.br/?p=143611",
        "post_type": "nav_menu_item"
      }
    ]
  }
}
```

The `guid` field explicitly contains `https://backend.blog.nubank.com.br/` — revealing the internal WordPress admin backend hostname.

### Internal Backend Confirmation

```bash
curl -sI "https://backend.blog.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```
**Response:**
```
HTTP/2 200
server: nginx
x-powered-by: WordPress VIP <https://wpvip.com>
```

`backend.blog.nubank.com.br` is a live, publicly accessible WordPress VIP instance. While admin login requires credentials (redirects to `wp-login.php`), the WordPress REST API is enabled with 717 routes accessible — including:
- `/jetpack/v4/purchase-token` (returns 401 with specific permission error codes)
- `/jetpack/v4/identity-crisis/url-secret` (returns 401)
- Post metadata accessible without auth (IDs, author IDs, timestamps)

### WordPress REST API — Post/Author Metadata

```bash
curl -s "https://backend.blog.nubank.com.br/wp-json/wp/v2/posts?per_page=3&_fields=id,author,date_gmt,status"
```
**Response:**
```json
[
  {"id": 148648, "author": 24, "date_gmt": "2026-08-28T14:52:20", "status": "publish"},
  {"id": 150261, "author": 4, "date_gmt": "2026-08-17T20:55:14", "status": "publish"},
  {"id": 149843, "author": 232, "date_gmt": "2026-08-05T17:55:39", "status": "publish"}
]
```

Author IDs (24, 4, 232, etc.) are Nubank WordPress internal user IDs. Author slugs were blocked by `rest_no_route`, suggesting `/wp/v2/users` is restricted, but author IDs remain accessible via post metadata.

---

## Attack Surface from Internal Domain

`backend.blog.nubank.com.br` running WordPress VIP with 717 REST API routes provides attack surface:
- Plugin-specific REST endpoints (Jetpack, Yoast, Redirection plugin, cron-control)
- If any Jetpack/WordPress VIP REST routes have authorization bypass, attacker knows the exact target
- Internal hostname can be used in further reconnaissance (server-side scanning, CSP leakage correlation)

---

## Remediation

| Issue | Fix |
|-------|-----|
| Internal hostname in `guid` field | Strip `guid` and internal WordPress fields before passing to Next.js frontend |
| `_next/data/` endpoint exposure | This endpoint is intentional Next.js behavior; filter WP-internal fields in `getStaticProps`/`getServerSideProps` before returning |
| WordPress REST API on backend | Restrict `backend.blog.nubank.com.br` to internal networks via IP allowlist; the frontend Next.js server should be the only consumer |
| Author IDs in REST API | Restrict `/wp-json/wp/v2/posts` or remove `author` field from public output |

---

## Notes

- No exploitation or write operations performed — passive read of public JSON endpoint
- `backend.blog.nubank.com.br` discovered from the `guid` field in the `_next/data/` response
- All requests used `X-Correlation-Id: bc-handle` as required
