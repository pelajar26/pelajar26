# Tripadvisor Bug Bounty — Scope Reference

> Program: Tripadvisor (Bugcrowd) — Safe Harbor, ongoing since 2019-01-14.
> This file is a local reference so testing stays strictly in-scope.
> Last synced from brief: 2026-03-06.

## Mandatory testing rules (apply to ALL activity)

- **User-Agent must contain the string `bugcrowd`** on every request
  (manual or automated).
- Use accounts containing the word `bugcrowd` for any content
  (e.g. `John Bugcrowd`, `alice.bugcrowd@gmail.com`).
- Add `bugcrowd` to a field of any form post that doesn't require account info.
- **Interacting with legitimate live properties or customers is strictly
  forbidden** — even minor actions (marking a review helpful, inviting to a
  trip). Use only test properties / your own entities.
- No inappropriate content, even on test properties.
- **No DoS / service disruption.** For any automated tooling: max **1 req/sec**
  and an identifying HTTP agent header.
- Reports must include demonstrated practical impact + full HTTP requests
  and responses.

### Test property field values (if creating a property)

| Field         | Value                       |
|---------------|-----------------------------|
| First name    | Must contain `Bugcrowd`     |
| Last name     | `Test`                      |
| Property Name | Must contain `Bugcrowd`     |
| City          | Atafu (location id 446951)  |
| Bank Country  | United Kingdom              |
| Account Number| 12345678                    |
| Sort Code     | 70 99 99                    |

Prefer existing test properties (Test Hotel 1/2, Test Vacation Rental 1/2,
Test Restaurant 1/2, Test Tour 1/2, Test Attraction 1/2).

## IN SCOPE

### Tier 1 — Payment (P1 $5000 / P2 $1250 / P3 $900 / P4 $250)
- `api.production.cde.tamg.cloud`
- `partnerapi.tapayments.com`, `partnerapi1.tapayments.com`, `partnerapi2.tapayments.com`
- `walletproxy.tapayments.com`, `walletproxy1.tapayments.com`, `walletproxy2.tapayments.com`
- CDE API has no public docs; endpoints discovered via payment flows on www.tripadvisor.com.
- **Caution:** never perform real payment manipulation; keep to auth/authz/info-disclosure checks.

### Tier 2 — Core web/API (P1 $3000 / P2 $900 / P3 $400 / P4 $150)
- `www.tripadvisor.com` + localized versions linked from header/footer
- `api.tripadvisor.com`
- `service.platform.tripadvisor.com`
- `gwapi.tripadvisor.com`, `gwapi1.tripadvisor.com`, `gwapi2.tripadvisor.com`
- Provided API key: `adf6d1b8-0aca-4b0c-a492-50530aadd7aa`
- Partner API docs: `http://api.tripadvisor.com/api/partner/2.0/doc?key=<APIKEY>`

### Tier 3 — Any publicly accessible Tripadvisor asset (P1 $1500 / P2 $450 / P3 $150 / P4 $50)
- Any publicly accessible Tripadvisor web asset/host (domains, IP space) EXCEPT out-of-scope below.
- `tamg.cloud` subdomains ending in `-sbx` are sandbox: "sensitive" data disclosure there is mostly NOT an issue.

### Mobile (P1 $3500 / P2 $750 / P3 $350 / P4 $75)
- Tripadvisor Android app `com.tripadvisor.tripadvisor`
- Tripadvisor iOS app id `284876795`
- Webviews from apps NOT published by Tripadvisor are out of scope.

### Vacation Rentals (points only, no bounty; sundowned)
- `rentals.tripadvisor.com`, `*.vacationhomerentals.com`, `*.holidaylettings.com`,
  `*.flipkey.com`, `*.niumba.com`, `*.housetrip.com`, `marlo.ext.tripadvisor.com`

### Bokun (points only, no bounty) — TEST env only
- `*.bokundemo.com`, `*.bokuntest.com` (alias "test", `extranet.bokuntest.com`,
  `widget.bokuntest.com`, `api.bokuntest.com`)
- Use `vulnscan` prefix in vendor/supplier name. Email `vulnerabilities@bokun.io`
  in advance if using automated tools; max 1 req/sec.
- **Production Bokun systems (listed out-of-scope) must NOT be tested.**

## OUT OF SCOPE — DO NOT TEST

Hosts:
- `*.bokun.eu`, `*.bokun.website`, `*.bokun.tools`, `*.bokun.team`,
  `*.bokun.io`, `*.bokun.is`, `*.bokun.com`, `*.bokun.app`
- `ir.tripadvisor.com`, `*.tripadviser.at`, `*.tripadvisor.cn`
- `*.tripadvisor.*/Trips`, `*.tripadvisor.*/Mobile*`, `*.tripadvisor.*/engineering`,
  `*.tripadvisor.*/WidgetEmbed-*`
- `spotlight-dev.tripadvisor.com`, `spotlight.tripadvisor.*`, `careers.tripadvisor.com`
- `*.tripadvisoradexpress.*`, `*.tripadvisorwifi.*`
- `taplus.*`, `tripadvisor-plus.*`, `tripadvisorplus.*`
- `*.experiences.zone`, `travelermail.com`, `*.bokunmobile.website`

Vulnerability classes out of scope:
- Info-stealer logs / exposed creds with no access to internal resources
  (accepted only if creds reach internal resources).
- HTTP header security findings (missing headers, etc.).
- IDOR in property-owner features (temporarily out of scope).
- Content fraud (rating manipulation, bogus listings, helpful-vote inflation).
- Mass content submission / account creation / spamming.
- DoS / service disruption.
- Social engineering, incl. open redirects (accepted only with impact beyond SE).
- Attacks requiring physical access; warranty-voiding (rooting) requirements.
- Webviews from non-Tripadvisor apps.
- Email misconfig (e.g. DMARC) on domains that don't send email.
- Mobile vulns requiring a malicious app installed → drastically reduced priority.
- Tripadvisor Plus functionality; Reputation Pro features in main app.
- Attacks against AI systems.

Independent brands (OUT OF SCOPE — separate/no program here):
- CruiseCritic, TheFork/LaFourchette, JetSetter, SeatGuru, Viator, HelloReco.
- Minority-investment domains (e.g. `traxo.com`) — ask via submission if unsure.
