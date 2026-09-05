# Tripadvisor Bug Bounty — Recon Notes & Perimeter Assessment

**Program:** Tripadvisor (Bugcrowd), Safe Harbor, ongoing.
**Date of testing:** 2026-09-05
**Tester marking:** all requests sent with a `User-Agent` containing
`bugcrowd` per program rules (no accounts created, no live properties or
customers interacted with, no payment flows exercised, no automated
flooding — low request volume, one request per host/path).

> **Status: no confirmed, impactful, reportable vulnerability yet.**
> This file records what was tested from an **unauthenticated, external**
> position, the perimeter's security posture, one CORS observation that was
> **verified to be non-impactful**, and a mapped attack surface to guide
> authenticated follow-up. It intentionally does **not** claim a finding
> that was not demonstrated.

## Scope compliance

- User-Agent contained `bugcrowd` on every request.
- Stayed on in-scope hosts only (`*.tripadvisor.com`, `*.tamg.cloud`,
  `*.tapayments.com`). No out-of-scope hosts touched (no Viator, TheFork,
  CruiseCritic, `*.bokun.io/.is/.com/.app`, `ir.`, `spotlight`, etc.).
- No interaction with live properties/customers; no content or account
  creation; no payment manipulation; no DoS/automation flooding.
- Reconnaissance was passive (Certificate Transparency) plus a small number
  of unauthenticated GETs to observe HTTP status / auth posture only.

## Perimeter security posture (what blocks unauthenticated testing)

| Asset class | Host(s) | Observed | Posture |
|---|---|---|---|
| Core web/API | `www.tripadvisor.com`, `gwapi1/2.tripadvisor.com` | `403` with `x-datadome: protected` | **DataDome** bot protection fronts the app |
| API redirect | `api.tripadvisor.com`, `gwapi.tripadvisor.com` | `301 → www.tripadvisor.com` | edge redirect (Envoy + CloudFront) |
| Payment (CDE/tapayments) | `partnerapi*.tapayments.com`, `walletproxy*.tapayments.com` | TLS closed mid-handshake (`HTTP 000`, `ws_closed_mid_exchange`) | **mutual TLS** required — no unauthenticated surface |
| Payment (CDE) | `api.production.cde.tamg.cloud` | `403 text/html (iso-8859-1)` | edge-gated |
| Service platform | `service.platform.tripadvisor.com` | `200` at `/` = `<NotImplemented/>`; other paths `400 {"message":"Certificate or LDAP token required"}` | **client-cert / LDAP** required; Jetty 9.4.26 |
| tamg management UIs | `argocd.*`, `argo-*`, `jupyterhub`, `atlantis`, `dashboard.*`, `kiali.*`, `dev.mlflow` | `403`/`404` (tiny `text/plain`) or `000` | ingress-gated or **internal-only** (not publicly resolvable) |

Net: the external, unauthenticated perimeter is well-defended. The
productive attack surface for this program is behind authentication
(Bugcrowd Ninja accounts, test properties, the provided Tier-2 API key,
client certs for CDE) — i.e. work that must be driven from the researcher's
own authenticated session, not blind external probing.

## CORS observation (verified NON-impactful — do NOT submit as-is)

`www.tripadvisor.com` and `gwapi1.tripadvisor.com` reflect an arbitrary
`Origin` and set `Access-Control-Allow-Credentials: true`:

```
$ curl -H 'Origin: https://evil-bugcrowd-poc.example.com' https://www.tripadvisor.com/ -D-
HTTP/1.1 403 Forbidden
access-control-allow-origin: https://evil-bugcrowd-poc.example.com
access-control-allow-credentials: true
```

This is the textbook CORS-credential-theft primitive **but only on the
DataDome `403` block page**. Verification against real responses shows the
misconfiguration does not extend to application data:

- `GET /robots.txt` (real `200`) → **no** `Access-Control-Allow-Origin` header.
- `GET /favicon.ico` (`200`) → `Access-Control-Allow-Origin: *` (**wildcard,
  no credentials** — not exploitable).
- `service.platform` real `200` → no `Access-Control-Allow-Origin`.

The only response reflecting `origin + credentials` is the bot-block page,
whose body is DataDome challenge HTML containing no victim-specific data,
and whose `Set-Cookie` is not readable via CORS. **No practical impact →
not a valid submission.** Worth re-checking on authenticated `2xx` API
responses (behind DataDome) — if the reflect-with-credentials header is
emitted by the edge on *those*, it becomes a real account-data-theft bug.
That check requires a valid session + DataDome clearance (researcher's own
browser), which is the recommended next step.

## Attack surface mapped (passive, via crt.sh)

`*.tamg.cloud` (Tripadvisor's AWS domain — the program explicitly
encourages testing here; "new services pop up weekly"). **378** unique
non-wildcard hostnames observed in Certificate Transparency logs. Full list
saved to `reports/tripadvisor-tamg-cloud-hosts.txt`.

High-interest categories (count of hostnames):

- `kafka` 52, `cruisecontrol` (Kafka mgmt) 5
- `kibana` 28 (Elasticsearch dashboards)
- `seldon` 15, `mlops` 22, `mlflow` 3, `jupyterhub` 1, `airflow` 1 (ML platform)
- `argo-ui` 15 (Argo Workflows UIs), `argocd` 10 (GitOps)
- `alertmanager` 11, `prometheus` 3, `kiali` 5 (Istio), `dashboard` 7
- `ambassador` 10 (API gateway, incl. `-admin`), `atlantis` 1 (Terraform), `vault` 1
- environment tags: `pit` 34, `dev` 31, `esc` 34, `dspe` 23, `mgs` 192, `istio` 12, `prod` 7

Publicly-reachable ones tested all returned generic ingress `403/404`
(gated); the rest resolve internally only. None exposed an unauthenticated
app in this pass. These remain the best area for continued, authenticated
or credential-carrying testing (per the program's own guidance).

## Recommended next steps (require researcher's authenticated context)

1. **CORS re-test on authenticated `2xx`:** in a real logged-in browser
   session (DataDome-cleared), replay an authenticated `www`/`gwapi` API
   call with `Origin: https://attacker.example` and inspect whether the
   edge still emits `ACAO: <reflected>` + `ACAC: true`. Only then is it
   reportable.
2. **Tier-2 Partner API** (`api.tripadvisor.com/api/partner/2.0/...`) with
   the provided key `adf6d1b8-0aca-4b0c-a492-50530aadd7aa`: test authz
   scoping / IDOR across partner objects (note: IDOR in *property-owner*
   features is temporarily out of scope).
3. **Test properties + Bugcrowd Ninja accounts:** exercise authenticated
   flows (trips, messaging, owner tooling) using only test entities and
   `bugcrowd`-tagged accounts — this is where the app's real logic lives.
4. **tamg.cloud continued monitoring:** re-run CT enumeration periodically;
   newly-published services are frequently exposed before hardening
   (program's own hint). Watch for any of the mapped management UIs becoming
   reachable without the ingress gate.
5. **`service.platform` (Jetty 9.4.26):** old server banner; behind
   client-cert/LDAP. Not exploitable unauthenticated, but note the version
   for any authenticated testing.

## Raw evidence (selected)

```
# DataDome fronting the app
$ curl -A 'bugcrowd...' https://www.tripadvisor.com/ -o /dev/null -w '%{http_code}\n'   # 403, x-datadome: protected

# Payment hosts require mTLS (connection closed mid-handshake)
$ curl -A 'bugcrowd...' https://partnerapi.tapayments.com/     # HTTP 000, ws_closed_mid_exchange
$ curl -A 'bugcrowd...' https://walletproxy.tapayments.com/    # HTTP 000, ws_closed_mid_exchange

# service.platform requires client cert / LDAP
$ curl -A 'bugcrowd...' https://service.platform.tripadvisor.com/health
{"code":400,"message":"Certificate or LDAP token required","unexpected":false}

# tamg management UIs — gated or internal
argocd.ndmad2.pit.tamg.cloud   -> 403 "Forbidden"
dev.mlflow.tamg.cloud          -> 403 "Forbidden"
argo-prod.dspe.tamg.cloud      -> 404 "404 page not found"
atlantis.ops.tamg.cloud        -> 000 (not publicly resolvable)
```
