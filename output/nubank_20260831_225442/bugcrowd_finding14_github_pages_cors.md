# Bugcrowd Finding #14 — GitHub Pages Subdomains Trusted by CORS with Credentials (Supply Chain Attack Vector)

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity (Standalone):** P2 High — External infrastructure (GitHub Pages) trusted by Nubank production CORS with credentials
**Severity (Chained):** P1 Critical — GitHub repo compromise or maintainer credential theft → full credentialed access to ALL Nubank production APIs
**VRT:** Server Security Misconfiguration > CORS Misconfiguration
**Related:** Finding #2 (nubank.com.br CORS wildcard), Finding #12 (cross-TLD CORS scope)

---

## Summary

Two Nubank-owned subdomains hosted on **GitHub Pages** (external GitHub infrastructure) are reflected with `Access-Control-Allow-Credentials: true` by ALL Nubank production microservices. Because these subdomains run JavaScript served by GitHub's infrastructure, their trustworthiness depends entirely on the security of the underlying GitHub repositories and Nubank's GitHub organization access controls — not solely on Nubank's own servers.

**Affected GitHub Pages subdomains:**
- `docs.share.nubank.com.br` — SFTP data-sharing documentation site (Jekyll)
- `keygen.share.nubank.com.br` — SFTP RSA key pair generation tool

Both serve public HTML+JavaScript pages with `Access-Control-Allow-Origin: *` (GitHub default for Pages), and both are reflected with credentials by Nubank's production Istio services.

---

## Technical Evidence

### 1. docs.share.nubank.com.br — Served by GitHub Pages

```bash
curl -sI "https://docs.share.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```

**Response:**
```
HTTP/2 200
server: GitHub.com
access-control-allow-origin: *
last-modified: Tue, 30 Jun 2026 01:42:18 GMT
x-github-request-id: EA2C:23288A:10223DA:122DCDA:6A96973E
x-github-edge-region: iad
```

Content: Jekyll site titled "Data Sharing with Nu via SFTP" — documentation for enterprise SFTP data sharing.

---

### 2. keygen.share.nubank.com.br — RSA Key Generation Tool on GitHub Pages

```bash
curl -sI "https://keygen.share.nubank.com.br/" -H "X-Correlation-Id: bc-handle"
```

**Response:**
```
HTTP/2 200
server: GitHub.com
access-control-allow-origin: *
x-github-request-id: [github-id]
```

Content: Client-side RSA 4096-bit key generation tool (`keygen.js`) using `window.crypto.subtle.generateKey`. The tool itself is cryptographically sound — key generation uses CSPRNG via Web Crypto API. No data is transmitted to servers during key generation.

**However**, the page loads and executes JavaScript served from GitHub's CDN under a trusted Nubank subdomain.

---

### 3. CORS Reflection — Both Subdomains Trusted with Credentials

```bash
# docs.share.nubank.com.br → prod-global-auth.nubank.com.br
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://docs.share.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://docs.share.nubank.com.br
# access-control-allow-credentials: true

# keygen.share.nubank.com.br → prod-global-auth.nubank.com.br
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://keygen.share.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://keygen.share.nubank.com.br
# access-control-allow-credentials: true
```

**Result:** Both GitHub Pages subdomains can make credentialed cross-origin requests to ALL Nubank production microservices, including PIX APIs and authentication APIs.

---

## Attack Chain — GitHub Repo Compromise → Full Account Takeover

```
[Step 1] Attacker targets Nubank GitHub organization
         ↓ Phishing/credential theft of developer with write access to GitHub repo
         ↓ OR: Compromise of CI/CD pipeline that has push access to Pages branch
         ↓ OR: Merge malicious PR if repo has open external contributions

[Step 2] Attacker adds malicious JavaScript to keygen.share.nubank.com.br
         ↓ Modifies keygen.js or adds a new script include to index.html
         ↓ GitHub Pages autodeploys the change within minutes
         ↓ All visitors to keygen.share.nubank.com.br now execute attacker's code

[Step 3] Malicious JavaScript executes on trusted Nubank origin
         ↓ keygen.share.nubank.com.br is *.nubank.com.br → trusted by CORS with credentials
         ↓ fetch('https://prod-global-auth.nubank.com.br/api/v1/user', {credentials:'include'})
         ↓ Returns authenticated user data (if victim is logged in to Nubank in same browser)
         ↓ fetch('https://pix.nubank.com.br/...', {credentials:'include'}) → PIX API access
         ↓ ALL prod microservices reachable with victim's credentials

[Impact]
         → Account takeover for all authenticated Nubank users who visit the keygen page
         → PIX payment theft (Brazil)
         → Cross-country: CORS scope accepts nubank.com.br across all TLDs (Finding #12)
```

---

## Additional Trusted Subdomains — Google Sites (Same Risk Pattern)

During CORS scope testing, two additional *.nubank.com.br subdomains hosted on Google Sites infrastructure were confirmed to be trusted with credentials:

```bash
curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://eashub.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://eashub.nubank.com.br
# access-control-allow-credentials: true

curl -sI "https://prod-global-auth.nubank.com.br/" \
  -H "Origin: https://clojure-south.nubank.com.br" \
  -H "X-Correlation-Id: bc-handle"
# access-control-allow-origin: https://clojure-south.nubank.com.br
# access-control-allow-credentials: true
```

- `eashub.nubank.com.br` → Google Sites "EAS Hub" vacation tracker
- `clojure-south.nubank.com.br` → Google Sites Clojure South conference site

Google Sites' strict CSP makes direct XSS exploitation difficult, but these sites represent the same architectural trust issue: third-party cloud infrastructure trusted with Nubank production CORS credentials.

---

## Risk Analysis

| Factor | Assessment |
|--------|------------|
| Root cause | Wildcard CORS regex trusts ALL `*.nubank.com.br` regardless of hosting provider |
| Attack difficulty | Medium — requires GitHub org compromise (developer phishing, CI/CD compromise) |
| Impact if exploited | P1 Critical — full credentialed access to all prod APIs for all authenticated visitors |
| Detection | GitHub audit log would show unauthorized push; browser sees valid HTTPS from trusted domain |
| User risk | Visitors to keygen/docs site who are also Nubank customers (enterprise SFTP users) |

---

## Remediation

| Issue | Fix |
|-------|-----|
| CORS wildcard scope | Replace regex with explicit allowlist — only Nubank-controlled, Istio-served origins should be trusted. Remove GitHub Pages and Google Sites subdomains from CORS trust. |
| Shared CORS policy | Implement separate CORS policies per service — high-sensitivity APIs (PIX, auth) should have the most restrictive allowed origins |
| GitHub Pages security | As interim: implement GitHub branch protection, require code review for changes to Pages-deployed branch; enable GitHub secret scanning and push protection |
| Audit trusted origins | Enumerate ALL `*.nubank.com.br` subdomains that resolve to third-party infrastructure (GitHub, Google, AWS) and remove them from CORS trust scope |

---

## Notes

- All CORS verification performed via HTTP header inspection only (no credential extraction)
- GitHub repository privacy status: private (403 from GitHub API) — reduces but does not eliminate risk
- keygen.js uses `window.crypto.subtle` for key generation — cryptographically sound; issue is CORS trust, not key generation quality
- No XSS or code injection was performed or tested
- All requests used `X-Correlation-Id: bc-handle` as required
