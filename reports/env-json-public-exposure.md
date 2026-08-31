# env.json Publicly Exposed — Information Disclosure & Secret Leak

**Severity:** Medium/High
**Target:** `empresa.bancoplata.mx` (secondary: `auth.bancoplata.mx`)
**Type:** Information Disclosure / Sensitive Data Exposure

## Summary

The frontend configuration file `env.json` is publicly accessible without
authentication at:

```
https://empresa.bancoplata.mx/envs/env.json
```

The response returns `200 OK` with a JSON payload containing production
secrets and internal infrastructure details. A similar, less sensitive
`env.json` is also exposed at `auth.bancoplata.mx` (only URLs and
environment names).

## Exposed Data

- **Google Maps API key** with no domain/referrer restriction:
  `AIzaSyCl•••••••••••••••••••••••••••••••`
- **Sentry DSN** (production error tracking):
  `https://1d8b5c2410f4b072794fb443542bf066@sentry.prime.diftech.org/183`
- **Internal API endpoint URLs** (gateway, payment-manager,
  processor-gateway, and others)
- **Auth `clientId`** and domain prefix
- **Production application version string**

## Impact

- **Google Maps API key abuse:** Since the key has no HTTP referrer
  restriction, it can be used by anyone to call Geocoding, Places, and
  Directions APIs billed to Plata's Google Cloud account. This was
  verified by successfully calling the API with `Referer: evil.com` and
  with no `Referer` header at all — resulting in direct financial risk
  (quota exhaustion / unexpected billing) to Plata.
- **Sentry DSN exposure:** An attacker with the DSN can submit spoofed
  error events into Plata's production error-tracking project, polluting
  monitoring data or potentially exploiting Sentry ingestion.
- **Internal endpoint enumeration:** Exposed gateway/payment-manager/
  processor-gateway URLs give an attacker a map of internal service
  topology, aiding further reconnaissance or targeted attacks.
- **Auth client metadata:** The exposed `clientId` and domain prefix
  reduce the effort needed to probe or abuse the authentication flow.

## Steps to Reproduce

1. No authentication is required.
2. Send a GET request to `https://empresa.bancoplata.mx/envs/env.json`.
3. Observe `200 OK` with the full production configuration JSON in the
   response body.
4. (Optional, to confirm Maps key abuse) Call the Google Maps Geocoding
   API using the extracted key with an arbitrary or absent `Referer`
   header and observe a successful response.

```
curl -s https://empresa.bancoplata.mx/envs/env.json
curl -s https://auth.bancoplata.mx/envs/env.json
```

## Recommendations

- Remove `env.json` (and any equivalent build-time config file) from the
  publicly served static asset path, or move it behind authentication.
- Rotate the exposed Google Maps API key and the Sentry DSN immediately.
- Restrict the new Google Maps API key by HTTP referrer and by the
  specific APIs it needs (Geocoding/Places/Directions only).
- Avoid embedding long-lived secrets or unrestricted keys in
  client-side/frontend configuration; prefer a backend proxy for calls
  that require a billable API key.
- Audit other subdomains (e.g. `auth.bancoplata.mx`) for the same
  exposure pattern and apply the same fix consistently.

---

# Additional Finding: Internal Kubernetes Service URL in Client-Side JavaScript

**Severity:** Low/Medium
**Target:** `bancoplata.mx`
**Type:** Information Disclosure / Internal Infrastructure Exposure

## Summary

The public marketing/security page at `https://bancoplata.mx/es/security`
renders server-side Next.js hydration state that contains a hardcoded
internal Kubernetes cluster DNS address. This value is embedded in the
page's JavaScript and is visible to any visitor in the page source.

## Exposed Data

Inside the `self.__next_f.push(...)` hydration payload embedded in the
HTML response:

```json
"snowplowMicroCollectorUrl": "http://snowplow-micro.frontend-website-constructor-prod.svc.cluster.local:9090"
```

This reveals:

- **Internal service name:** `snowplow-micro`
- **Kubernetes namespace:** `frontend-website-constructor-prod`
- **Protocol and port:** `http` on port `9090`
- **Cluster DNS suffix:** `.svc.cluster.local` (standard Kubernetes internal DNS)

## Impact

- **Infrastructure topology disclosure:** The Kubernetes namespace name
  (`frontend-website-constructor-prod`) confirms the production environment
  name and naming convention used internally. Combined with other leaked
  service URLs (from `env.json`), this builds a more complete picture of
  Plata's internal service topology.
- **Snowplow collector identification:** Knowing the internal collector
  address could assist an attacker who gains internal network access (e.g.
  via SSRF or container escape) in locating and exfiltrating analytics
  data or poisoning the event stream.
- **Build-time misconfiguration signal:** The fact that a server-side
  rendering variable pointing to an internal URL is propagated into
  client-side state indicates that build-time or runtime environment
  variable handling is leaking internal configuration into the public
  JavaScript bundle — the same root cause class as the `env.json` finding.

## Steps to Reproduce

1. Open `https://bancoplata.mx/es/security` in a browser or with curl.
2. View the page source (Ctrl+U) or inspect the raw HTTP response body.
3. Search for `snowplow` or `svc.cluster.local` in the source.
4. Observe the internal Kubernetes DNS URL in the Next.js hydration JSON.

```
curl -s https://bancoplata.mx/es/security | grep -o 'snowplowMicroCollectorUrl[^"]*"[^"]*"'
```

## Recommendations

- Audit all Next.js pages for server-side environment variables that are
  unintentionally passed to `props` or page data and serialised into
  client-side state.
- Internal service URLs (those ending in `.svc.cluster.local` or similar)
  must never appear in any public HTTP response body.
- Use Next.js's `NEXT_PUBLIC_` prefix convention strictly: only variables
  explicitly intended for client-side use should carry that prefix; all
  other variables remain server-side only.
- Consider a build-time linter or CI check that scans the compiled
  JavaScript bundle and page HTML for patterns like `svc.cluster.local`,
  `internal`, or other known-internal hostnames.
