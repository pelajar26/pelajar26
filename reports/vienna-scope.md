# City of Vienna Managed Bug Bounty — Scope Reference

> Program: City of Vienna (Stadt Wien) — Bugcrowd, Safe Harbor, public,
> ongoing since 2025-01-16. Government + healthcare.
> Last synced from brief: 2026-03-03.

## ⚠️ NONDISCLOSURE (critical)

This engagement **does not allow disclosure**. Vulnerability details found
here must **not** be released publicly. Do **not** commit exploit details,
PoCs, or confirmed-finding specifics to any public repository. Keep them in
the Bugcrowd submission / private notes only. This repo file intentionally
contains **only scope + methodology + public CT-log host data**.

## Testing rules / good-faith conduct

- Testing authorized **only** on in-scope targets below. Any Vienna
  domain/IP not listed is out of scope.
- Self-provision accounts using a **@bugcrowdninja.com** email. Only touch
  **user data belonging to accounts you created**.
- **No DDoS / load-based DoS.** (Single-request DoS *is* in scope.)
- Healthcare systems (AKH, Gesundheitsverbund, wienkav): extra caution — no
  patient/real-user data, no disruption.
- Do not touch support/contact forms (out of scope).
- Rating: Bugcrowd VRT; priority may be adjusted by likelihood/impact (with
  explanation + appeal).

## Excluded submission types (do NOT report these)

- **P4 and P5** vulnerabilities
- **CSRF**
- **No Rate Limiting**
- **DMARC / DKIM / SPF** issues
- **Request Smuggling** (temporarily excluded while being fixed centrally)

→ Focus on **P1–P3 impact**: auth bypass, access control / IDOR (own
accounts only), injection (SQLi/SSTI/command), SSRF, sensitive data
exposure / secret leak, RCE, stored/impactful XSS, exposed admin panels,
authz flaws in `mein.wien.gv.at` broker API, etc.

## N-Day policy

Publicly released N-day bugs become in-scope **21 days** after release.

## IN SCOPE

### Web (P1 $2400–3500 / P2 $750–2400 / P3 $200–750)
- `www.wien.gv.at`, `*.wien.gv.at`
- `*.magwien.gv.at`
- `wien.at`, `*.wien.at`
- `stp.wien.gv.at`
- `www.gesundheitsverbund.at`, `*.gesundheitsverbund.at`
- `*.wienkav.at`
- `www.akhwien.at`, `*.akhwien.at`
- `secumails.gesundheitsverbund.at` (FTAPI secure mail)
- `mein.wien.gv.at` (Mein Wien portal)
- `mein.wien.gv.at/broker/api/*` (Mein Wien API)
- `wibi.wien.gv.at`

### Azure / M365
- `*.stadtwien.onmicrosoft.com`
- `schulenwien.onmicrosoft.com`
- `stadtwien-my.sharepoint.com`

### Network ranges (Network + Website testing)
- AS6720: `141.203.0.0/16`, `217.149.224.0/20`
- AS6720 IPv6: `2a00:1ba0:2::/48`, `2a00:1ba0:3::/48`
- AS16314: `217.116.64.0/20`

### Mobile apps
- City of Vienna Google Play (developer id: Stadt Wien)
- City of Vienna iOS (developer: Stadt Wien)

## OUT OF SCOPE

- `https://www.wien.gv.at/advuew/*`
- Public Network / Veranstaltungsnetz: `141.203.188.0/22`
- Any Vienna domain or IP **not** listed above
- Support / contact forms
- User data not belonging to your own created/provided accounts
- Phishing
- Distributed / load-based DoS (single-request DoS is in scope)
- Leaked credentials from leak databases / purchased
