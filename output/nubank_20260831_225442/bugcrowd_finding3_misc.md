# Bugcrowd Vulnerability Report
## Finding 3: Miscellaneous Security Issues — Session Cookie Missing HttpOnly, Internal Portal Exposure

---

### Title
Multiple Low-Severity Security Issues: Missing `HttpOnly` Cookie Flag (link.nubank.com.br) and Internal Portal Accessible via Public DNS (links.nubank.com.br)

---

### Vulnerability Type
**Issue A:** CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)
**Issue B:** CWE-200 (Exposure of Sensitive Information — Internal Portal)

---

### Severity
**P4 — Low** (standalone; amplifier if XSS found on link.nubank.com.br)

---

### Affected Assets

| Asset | Issue | Criticality |
|-------|-------|-------------|
| `link.nubank.com.br` | Missing HttpOnly on session cookie | Low (P4) |
| `links.nubank.com.br` | Internal "Intaface" portal on public DNS | Info (P5) |

---

### Issue A: `link.nubank.com.br` — Session Cookie Missing HttpOnly Flag

**Description:**
The payment link service (`link.nubank.com.br`, powered by Branch.io deep linking) sets a session cookie `_s` without the `HttpOnly` flag:

```
Set-Cookie: _s=<value>; Max-Age=31536000; Path=/; Expires=...; Secure
```

Notice: `HttpOnly` is absent. This makes the `_s` cookie accessible to JavaScript via `document.cookie`.

**Evidence:**
```bash
$ curl -s -D - -o /dev/null https://link.nubank.com.br/
Set-Cookie: _s=AKhyhYWV...; Max-Age=31536000; Path=/; Expires=...; Secure
# No HttpOnly flag
```

**Impact:**
If an XSS vulnerability is found on `link.nubank.com.br` (or if the CORS misconfiguration from Finding 2 is extended to this subdomain via script injection), an attacker could extract the `_s` session token via `document.cookie`. The `link.nubank.com.br` domain is in scope as a Nubank subdomain and CORS-trusted (without credentials) under the Finding 2 CORS misconfiguration.

**Remediation:**
Add the `HttpOnly` flag to all session cookies:
```
Set-Cookie: _s=<value>; HttpOnly; Secure; SameSite=Strict; Path=/
```

---

### Issue B: `links.nubank.com.br` — Internal Portal ("Intaface") on Public DNS

**Description:**
An internal Nubank portal titled "Log In | Intaface" is publicly DNS-resolvable and accessible at `links.nubank.com.br`. The application reveals:

1. **Application name**: "Intaface" (internal analytics/link management platform)
2. **Swagger documentation**: `/swagger` path exists (redirects to login, not 404) — API docs available to authenticated users
3. **API surface**: `/api` returns 401 (not 404), confirming API endpoints exist
4. **Admin path**: `/admin` path exists (redirects to login)
5. **Analytics**: Segment.io tracking loaded in the login page

**Evidence:**
```bash
$ curl -s https://links.nubank.com.br/login | grep title
<title>Log In | Intaface</title>

$ curl -o /dev/null -w "%{http_code}" https://links.nubank.com.br/swagger
302 → https://links.nubank.com.br/login?ReturnUrl=%2Fswagger

$ curl -o /dev/null -w "%{http_code}" https://links.nubank.com.br/api
401
```

**Impact:**
The portal requires authentication to access. However, its public DNS exposure reveals the existence of an internal analytics platform with Swagger API documentation. An attacker with credentials (e.g., via credential stuffing or phishing of a Nubank employee) could access the full API documentation and exploit IDOR or business logic vulnerabilities in the internal platform.

**Additional note:** `robots.txt` disallows all crawling (`Disallow: /`), but this alone doesn't protect the portal from discovery.

**Remediation:**
1. Move `links.nubank.com.br` behind VPN/Zero Trust access control (not publicly routable)
2. Or: ensure it requires Nubank SSO/SAML with MFA before exposing to the internet
3. Add security headers: `Strict-Transport-Security`, `Content-Security-Policy`
4. Remove Segment tracking from the login page (analytics before auth is unnecessary)

---

### Additional: gRPC Service Enumeration Extension (Finding 1 update)

`prod-global-ouroboros.nu.com.mx` is confirmed as a gRPC service (not REST):

```bash
$ curl -s -D - -o /dev/null \
  -H "Content-Type: application/grpc" \
  -H "TE: trailers" \
  https://prod-global-ouroboros.nu.com.mx/

content-type: application/grpc
grpc-status: 16   # 16 = UNAUTHENTICATED
```

gRPC reflection service endpoints exist at:
- `/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo` (HTTP 200, gRPC 16)
- `/grpc.reflection.v1.ServerReflection/ServerReflectionInfo` (HTTP 200, gRPC 16)

This adds gRPC protocol mapping to the service topology disclosed in Finding 1. With authentication, gRPC reflection would expose the full .proto service definition for `ouroboros`.

---

*Reported via Bugcrowd — Nubank Bug Bounty Program*
*Researcher: naqkhaie.f055@gmail.com*
*Scan date: 2026-09-01*
