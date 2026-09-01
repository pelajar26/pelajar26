# Bugcrowd Vulnerability Report — ADDENDUM
## Finding 2 Update: CORS Additional Scope — HTTP Origins, Nested Subdomains, and Custom Ports

---

### Title (Addendum to Finding 2)
CORS Misconfiguration Severity Amplifiers: HTTP Origins, Nested Subdomains, and Non-Standard Ports Also Reflected with credentials:true

---

### Severity
**P1 — Critical** (same chained severity as main Finding 2, with additional attack vectors)

---

### Summary

Additional testing on Finding 2 revealed three severity amplifiers beyond the original report. All three expand the attack surface for the CORS credential leakage chain.

---

### Additional CORS Reflection Behaviors Confirmed

**1. HTTP Origins Reflected (Not Just HTTPS)**

The CORS policy reflects `http://` origins, not just `https://`. This is an additional risk:

```bash
curl -s -D - -o /dev/null \
  -H "Origin: http://evil.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle" \
  https://prod-global-auth.nubank.com.br/
```

Response:
```
access-control-allow-origin: http://evil.nubank.com.br
access-control-allow-credentials: true
```

**Impact**: Any HTTP-served content on a Nubank subdomain (including temporary redirects, legacy pages, or infrastructure serving over HTTP) can serve as a CORS-trusted origin. An attacker controlling HTTP content on any `*.nubank.com.br` path can launch credentialed cross-origin requests to HTTPS production APIs.

---

**2. Nested Subdomains Reflected (Any Depth)**

Multi-level subdomain nesting is accepted:

```bash
curl -s -D - -o /dev/null \
  -H "Origin: https://a.b.c.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle" \
  https://prod-global-auth.nubank.com.br/
```

Response:
```
access-control-allow-origin: https://a.b.c.nubank.com.br
access-control-allow-credentials: true
```

**Impact**: Confirms the CORS regex is `.*\.nubank\.com\.br` (or similar pattern without anchoring), trusting all subdomain depths. Services like `staging-maxwell.nu.com.mx`, `noc.nubank.com.br` sub-paths, or any future deep-nested subdomain all qualify as trusted CORS origins.

---

**3. Custom Port Reflected (Non-Standard Ports)**

Non-standard port numbers in the origin are also reflected:

```bash
curl -s -D - -o /dev/null \
  -H "Origin: https://evil.nubank.com.br:8443" \
  -H "X-Correlation-Id: bc-handle" \
  https://prod-global-auth.nubank.com.br/
```

Response:
```
access-control-allow-origin: https://evil.nubank.com.br:8443
access-control-allow-credentials: true
```

**Impact**: Even if an attacker cannot serve content on port 443 of a Nubank subdomain, serving on any alternative port (e.g., 8080, 8443, 3000) would be trusted as a CORS origin with credentials.

---

### Chain Implications

Combined with the original finding, the CORS trust surface includes:
- `https://any-subdomain.nubank.com.br` (original)
- `http://any-subdomain.nubank.com.br` (new — HTTP also trusted)
- `https://any.nested.subdomain.nubank.com.br` (new — any depth)
- `https://any-subdomain.nubank.com.br:PORT` (new — any port)

The misconfiguration is confirmed not just on Istio/Envoy prod-* services, but also on:
- `prod-global-webapp-proxy.nubank.com.br` (Cloudflare-fronted)
- `prod-global-magnitude.nu.com.mx` (payment processing service)
- All tested prod-* endpoints across all four TLDs (65+ services)

---

### Additional Service: gRPC Protocol Identified

During extended enumeration, `prod-global-ouroboros.nu.com.mx` was confirmed as a **gRPC service**:

```bash
curl -s -D - -o /dev/null \
  -H "Content-Type: application/grpc" \
  -H "TE: trailers" \
  https://prod-global-ouroboros.nu.com.mx/
```

Response:
```
HTTP/2 200
content-type: application/grpc
grpc-status: 16
```

`grpc-status: 16` = `UNAUTHENTICATED` — confirms gRPC protocol and authentication requirement.

gRPC reflection endpoints accessible (HTTP 200, but gRPC-level auth required):
- `/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`
- `/grpc.reflection.v1.ServerReflection/ServerReflectionInfo`

**Impact (with authentication)**: Once authenticated, gRPC server reflection would expose the full `.proto` service definition including all method names, input/output message types, and field names for the `ouroboros` internal service.

---

*Reported via Bugcrowd — Nubank Bug Bounty Program*
*Researcher: naqkhaie.f055@gmail.com*
*Scan date: 2026-09-01*
