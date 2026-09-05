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
>
> Two testing passes are recorded: **Pass 1** (main perimeter) below, and
> **Pass 2** (subdomain enumeration, takeover sweep, legacy Vacation-Rental
> brands, email auth) in the section "Pass 2" near the end.

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

---

# Pass 2 — subdomain enumeration, takeover, legacy brands, email auth

Same scope-compliant methodology (bugcrowd UA, low volume, passive-first).

## Subdomain enumeration (passive, CT logs)

- `*.tripadvisor.com`: **666** unique non-wildcard hostnames →
  `reports/tripadvisor-com-subdomains.txt`.
- Vacation-Rental brands (flipkey/holidaylettings/niumba/housetrip/
  vacationhomerentals): **81** hostnames →
  `reports/tripadvisor-vacation-rental-hosts.txt`.
- `*.tamg.cloud`: **378** (Pass 1) → `reports/tripadvisor-tamg-cloud-hosts.txt`.

Most `*.corp.tripadvisor.com`, `*.sip.corp`, `*.d.`, `*.n.` names are
internal DC / telephony / DB infra (CUCM, Finesse, LDAP, dbproxy, maven-proxy)
— not publicly resolvable and not appropriate to probe; left untouched.

Public-facing dev/test candidates fingerprinted: `api-test`,
`internalapi-dev`, `dev-api.content`, `business-qa`, `compasstest`,
`helptest`, `docs.dev`, `gitlab.dev`, `ladmin`, `hare-api` → all `502`
(egress gateway cannot reach a dead upstream — decommissioned backends, not
exploitable). `dev-terra.tripadvisor.com` → AWS API Gateway returning
`{"message":"Forbidden"}` (auth-gated). `backup-api`, `api-bing` → redirect
to www / DataDome.

## Subdomain-takeover sweep — RESULT: none confirmed

Method: DoH (`dns.google`) `A`/`CNAME` for all 748 tripadvisor.com + VR
hosts; flag NXDOMAIN-with-CNAME and CNAMEs to takeover-prone third parties;
verify candidates.

- Every live CNAME to CloudFront / Fastly / Akamai / ExactTarget resolves to
  real IPs → distributions/services are **claimed** → not takeoverable.
- NXDOMAIN-with-CNAME hits point to **internal `*.tripadvisor.com` targets**
  (e.g. `nokiamaps.*` ccTLDs → `nokiamaps.tripadvisor.com`,
  `livesite-maven.b` → `maven.dev.tripadvisor.com`) — internal names cannot
  be claimed by a third party → **no takeover**.
- `spotlight.tripadvisor.*` / `spotlight-dev` → CNAME to
  `*.otainsight.com` (dangling) but these hosts are **explicitly OUT OF
  SCOPE** — not pursued.
- `tripwow.tripadvisor.com` → CNAME `d2a9j3gvoquhak.cloudfront.net`, which
  returns **NOERROR with no A record** = a **disabled (still-owned)**
  CloudFront distribution → the alternate-domain claim is still held by
  Tripadvisor's account → **not takeoverable** (just a dead `502` endpoint).
- `zuora-dev.tripadvisor.com` → full **NXDOMAIN**, no dangling CNAME → dead,
  nothing to claim.

## Legacy Vacation-Rental brands (points-only scope; sundowned)

- `flipkey.com`, `niumba.com`, `holidaylettings.com`,
  `vacationhomerentals.com` (+ `www`): static archived HTML served from
  **S3 behind CloudFront** (`Server: AmazonS3`, `Via: …cloudfront`). Origin
  bucket name is not leaked (CloudFront-fronted); no public listing exposed;
  flipkey/niumba pages are ~1.5 KB stubs with no JS/secrets.
- `housetrip.com`: live **Next.js** (Cloudflare). Hydration state + chunk
  refs contain only `bstatic.com` image URLs and `www.housetrip.com` — no
  internal hosts, no `svc.cluster.local`, no keys (checked specifically
  because the earlier env.json report found a k8s URL in Next.js hydration).
- Legacy origin hosts `api.flipkey.com` / `propertymanagers.flipkey.com` /
  `secure2.flipkey.com` (199.102.235.x, 185.61.97.x): TCP up but **reset the
  TLS handshake** → not reachable for testing from here.
- `rentals.tripadvisor.com` → `503` (awselb, dead backend).

## Email authentication (DMARC) — low severity / eligibility-dependent

Eligible only for domains that send email (per program out-of-scope note);
Vacation-Rental brands are points-only. Observed via DoH TXT `_dmarc.<d>`:

| Domain | DMARC | Note |
|---|---|---|
| `tripadvisor.com` | `p=reject` | strong (good) |
| `niumba.com` | `p=quarantine; pct=30` | ~70% of failing mail not quarantined |
| `holidaylettings.com` | `p=quarantine; pct=30` | weak enforcement |
| `vacationhomerentals.com` | `p=quarantine; pct=10` | ~90% not enforced |
| `flipkey.com` | `p=none` | monitoring only → spoofable if it sends mail |
| `housetrip.com` | **no `_dmarc` record** | fully spoofable if it sends mail |

These are at best low-severity (P4/informational) and only on points-only
brands; confirm each domain actually sends mail (MX/SPF) before considering
a submission.

## Pass 2 conclusion

No confirmed impactful vulnerability. The external unauthenticated surface
is either hardened (Pass 1) or decommissioned/static (Pass 2). The realistic
path to a bounty here is **authenticated** testing (Bugcrowd Ninja accounts,
test properties, the Tier-2 API key, a DataDome-cleared browser) — see the
recommended next steps above.
