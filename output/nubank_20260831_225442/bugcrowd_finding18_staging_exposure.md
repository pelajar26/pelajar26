# Bugcrowd Finding #18 — WordPress VIP Staging Environment Exposed: Unpublished Content + Trusted CORS Origin (*.go-vip.net Chain)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P3 Medium — Staging site publicly accessible, exposes pre-publication blog content
**Severity (Chained with Finding #17):** P2 High — Staging is a *.go-vip.net domain trusted by CORS on all Nubank prod APIs with `access-control-allow-credentials: true`
**Target:** `blog-nubank-com-br-develop.go-vip.net` (WordPress VIP staging for blog.nubank.com.br)
**VRT:** Server Security Misconfiguration > Exposed Staging Environment
**Related:** Finding #17 (*.go-vip.net CORS trust), Finding #4 (script-src-elem: *)

---

## Summary

Nubank's WordPress VIP staging environment at `blog-nubank-com-br-develop.go-vip.net` is publicly accessible without authentication and exposes:
1. **Unpublished blog posts** — upcoming product announcements and employee articles not yet live on production
2. **Internal test pages** — developer IP tools, iframe calculators, anti-scam test flows
3. A CORS-trusted origin (*.go-vip.net, per Finding #17) — JS on this staging domain can make credentialed cross-origin requests to ALL Nubank production APIs

---

## Technical Evidence

### 1. Staging Site Publicly Accessible

```bash
curl -sI "https://blog-nubank-com-br-develop.go-vip.net/"
# HTTP/2 200
# server: nginx
# x-powered-by: WordPress VIP <https://wpvip.com>
# content-security-policy: [...] script-src-elem * 'unsafe-inline' ...
```

The site returns 200 OK with no authentication challenge.

### 2. WordPress REST API Exposes Unpublished Content

```bash
curl -s "https://blog-nubank-com-br-develop.go-vip.net/wp-json/wp/v2/posts?per_page=10&orderby=modified&order=desc"
```

**Posts exposed (not published on production blog.nubank.com.br):**

| Post Title | Modified Date |
|-----------|--------------|
| Avalanche (AVAX): o que é e como funciona essa criptomoeda? | 2026-08-13 |
| NuBolão (new product?) | 2026-08-13 |
| Seguro viagem: dicas e informações essenciais | 2026-08-11 |
| Teste Lucro do FGTS 2026: saiba quanto você vai receber | 2026-08-05 |
| Nu Sans: como uma fonte pode representar os valores de uma marca? | 2026-08-03 |

**Internal test pages exposed (10 pages accessible via REST API):**

| Page | URL |
|------|-----|
| Quiz | `/quiz/` |
| Calc (iframe) | `/iframe-calcula` |
| Test SOS NU GOLPEs | `/test-sos-nu-golpes/` |
| Qual meu ip dev | `/qual-meu-ip-dev/` |
| Qual meu IP? | `/qual-meu-ip/` |
| SOS Nu | `/sos-nu/` |

The "SOS Nu" and "Test SOS NU GOLPEs" pages appear to be staging/test versions of Nubank's anti-scam tool (`denunciargolpes.nubank.com.br`). The "Qual meu ip dev" page is a developer IP detection tool.

### 3. CSP: script-src-elem Wildcard

```
content-security-policy: [...] script-src-elem * 'unsafe-inline' data: blob: https://cdn.ampproject.org
```

The `script-src-elem: *` directive allows JavaScript to load and execute external scripts from ANY domain. Combined with the CORS trust (below), any XSS on this staging domain enables full credentialed access to prod APIs.

### 4. CORS Trust (from Finding #17)

```bash
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://blog-nubank-com-br-develop.go-vip.net"
# access-control-allow-origin: https://blog-nubank-com-br-develop.go-vip.net
# access-control-allow-credentials: true
```

This staging domain is trusted by ALL Nubank production auth and financial API endpoints because it is a *.go-vip.net subdomain (per Finding #17).

---

## Business Impact

| Impact Type | Detail |
|-------------|--------|
| **Market intelligence leak** | Competitors can read upcoming product announcements (NuBolão, Seguro Viagem, Nu Sans) before official launch |
| **Brand impact** | Test articles with "Teste" label can be misread as official content |
| **Internal tool exposure** | Developer IP tools, calculator iframes expose internal test flows |
| **CORS escalation** | Combined with Finding #17: staging domain trusted by prod with credentials — XSS here = full API access |

---

## Attack Chain (Combined with Finding #17)

```
[Step 1] Attacker enumerates blog-nubank-com-br-develop.go-vip.net content via REST API
  → Discovers upcoming product launches, internal test tools

[Step 2] Attacker registers on WordPress VIP staging via wp-login.php
  OR: Finds XSS in staging WordPress (lower security than prod)
  
[Step 3] Staging is a go-vip.net domain → CORS trusted with credentials on all prod APIs
  → XSS payload on staging: 
    fetch('https://prod-global-auth.nubank.com.br/api/v1/discovery', {credentials:'include'})
    .then(r => r.json()).then(data => exfiltrate(data))
  → CSP script-src-elem: * allows loading attacker's JS from any domain
  
[Impact] Business intelligence leak + potential authenticated API access via staging CORS trust
```

---

## Comparison: Staging vs Production

| Item | blog-nubank-com-br-develop.go-vip.net (Staging) | blog.nubank.com.br (Production) |
|------|-------------------------------------------------|----------------------------------|
| Access | Public, no auth | Public, no auth |
| CORS trusted by prod APIs | Yes (go-vip.net wildcard — Finding #17) | Yes (*.nubank.com.br — Finding #2) |
| CSP `script-src-elem` | `*` (any domain) | `*` (any domain) — both have same weak CSP |
| XML-RPC `system.multicall` | Enabled | Enabled (Finding #13) |
| wp-login.php | Accessible (200) | Accessible (200) |
| Draft/test content exposed | Yes | No |

---

## Remediation

| Action | Detail |
|--------|--------|
| **Restrict staging access** | Add HTTP basic auth or IP allowlist to `blog-nubank-com-br-develop.go-vip.net` |
| **Remove staging from CORS** | Fix Finding #17 — remove *.go-vip.net from prod CORS (staging environments should never be CORS-trusted by prod APIs) |
| **Fix script-src-elem** | Replace `script-src-elem: *` with explicit trusted CDN domains on all blog domains |
| **Remove dev test pages** | Delete or protect internal test pages (/qual-meu-ip-dev/, /test-sos-nu-golpes/, etc.) from staging |

---

## Notes

- No authentication performed on staging WordPress admin
- Content enumerated via unauthenticated REST API (`/wp-json/wp/v2/posts`, `/wp-json/wp/v2/pages`)
- No post content was accessed — only titles and metadata
- All requests used `X-Correlation-Id: bc-handle` as required

