# Bug Bounty Toolkit

Automated recon, vulnerability scanning, dan exploit-assist toolkit untuk mana-mana bug bounty program.

## Install Semua Tools

```bash
chmod +x install.sh && ./install.sh
```

| Tool | Fungsi |
|------|--------|
| subfinder | Subdomain enumeration |
| httpx | Live host detection + tech fingerprint |
| ffuf | Directory & parameter fuzzing |
| katana | Web crawler untuk JS recon |
| nuclei | CVE & vulnerability scanning |
| dnsx | DNS resolution |
| naabu | Port scanning |
| gau / waybackurls | URL discovery dari archive |
| subjack | Subdomain takeover detection |
| dalfox | XSS scanner |
| arjun | Parameter discovery |
| interactsh-client | OOB server untuk SSRF/blind testing |

---

## Scripts

### 1. `recon.sh` — Full Recon Pipeline
```bash
chmod +x recon.sh
./recon.sh -d example.com
```
Subfinder → httpx → ffuf. Output tersusun dalam `output/example.com_TIMESTAMP/`.

**Options:**
```
-d  Target domain (required)
-o  Output directory
-w  Wordlist ffuf (default: wordlists/common.txt)
-t  Threads (default: 50)
-r  Rate limit req/sec (default: 150)
-s  Skip directory fuzzing
```

---

### 2. `scripts/vuln_scan.sh` — Vulnerability Scanner
```bash
./scripts/vuln_scan.sh -l output/example.com_*/live_hosts.txt
```
- Nuclei (CVEs + misconfigs)
- Open Redirect detection
- CORS misconfiguration
- Security headers check
- Exposed files: `.env`, `.git`, backup, phpinfo, Swagger, GraphQL

**Options:**
```
-l  Live hosts file (required)
-s  Severity: critical,high,medium,low,info
-o  Output directory
-t  Nuclei templates path
```

---

### 3. `scripts/js_recon.sh` — JavaScript Analysis
```bash
./scripts/js_recon.sh -l output/example.com_*/live_hosts.txt
```
- Crawl semua JS files dengan katana
- Extract API endpoints
- Detect hardcoded secrets: AWS keys, JWT, GitHub tokens, OpenAI keys
- Pattern matching untuk credentials

---

### 4. `scripts/param_fuzz.sh` — Parameter Discovery
```bash
./scripts/param_fuzz.sh -l output/example.com_*/live_hosts.txt
```
- Arjun parameter bruteforce (GET + POST)
- Harvest params dari Wayback Machine & GAU
- Auto-classify params: XSS, SSRF, SQLi, Open Redirect candidates
- Quick reflection test untuk potential XSS

**Options:**
```
-l  Hosts/URLs file (required)
-m  HTTP methods: GET,POST,JSON (default: GET,POST)
-o  Output directory
-t  Threads
```

---

### 5. `scripts/bypass_403.sh` — 403 Bypass Techniques
```bash
./scripts/bypass_403.sh -u https://example.com/admin
./scripts/bypass_403.sh -l output/example.com_*/403_urls.txt
```
Teknik yang ditest:
- Path manipulation: `/./ /..;/ trailing dot/slash double-slash UPPERCASE`
- HTTP Method Override: HEAD, POST, PUT, PATCH, X-HTTP-Method-Override
- IP spoofing headers: X-Forwarded-For, X-Real-IP, CF-Connecting-IP, dll
- URL encoding tricks: double encode, unicode
- Content-Type tricks: JSON, XML
- X-Original-URL / X-Rewrite-URL

---

### 6. `scripts/subdomain_takeover.sh` — Takeover Detection
```bash
./scripts/subdomain_takeover.sh -l output/example.com_*/subdomains_raw.txt
```
- Nuclei subdomain-takeover templates
- Subjack scan
- Manual CNAME + fingerprint check untuk 25+ services:
  GitHub Pages, Heroku, Shopify, AWS S3, Fastly, Ghost, Tumblr, Surge, Bitbucket, Zendesk, HubSpot, Fly.io, Render, dll
- S3 bucket: unclaimed bucket + listing check
- NXDOMAIN detection

---

### 7. `scripts/report_gen.py` — HTML Report
```bash
python3 scripts/report_gen.py -d output/example.com_TIMESTAMP/
```
Generate report HTML dalam browser dengan semua findings.

---

## Custom Nuclei Templates (`templates/nuclei/`)

| Template | Detects |
|----------|---------|
| `exposed-env-files.yaml` | `.env` files dengan credentials |
| `cors-misconfig.yaml` | CORS dengan reflected origin + credentials |
| `graphql-introspection.yaml` | GraphQL schema exposure |
| `ssrf-detect.yaml` | SSRF via common URL params (OOB) |
| `open-redirect-params.yaml` | Open redirect via 20+ params |
| `jwt-none-alg.yaml` | JWT none algorithm bypass |

Guna custom templates:
```bash
nuclei -l output/*/live_hosts.txt -t templates/nuclei/
```

---

## Pipeline Penuh (Satu Command)

```bash
DOMAIN="example.com"

# Recon
./recon.sh -d "$DOMAIN"
OUT=$(ls -td output/${DOMAIN}_* | head -1)

# Vuln scan
./scripts/vuln_scan.sh -l "$OUT/live_hosts.txt" -o "$OUT/vuln/"

# JS recon
./scripts/js_recon.sh -l "$OUT/live_hosts.txt" -o "$OUT/js/"

# Parameter discovery
./scripts/param_fuzz.sh -l "$OUT/live_hosts.txt" -o "$OUT/params/"

# Subdomain takeover
./scripts/subdomain_takeover.sh -l "$OUT/subdomains_raw.txt" -o "$OUT/takeover/"

# Custom nuclei templates
nuclei -l "$OUT/live_hosts.txt" -t templates/nuclei/ -o "$OUT/custom_nuclei.json"

# 403 bypass (manual — supply the 403 URLs)
# ./scripts/bypass_403.sh -u https://example.com/admin

# HTML Report
python3 scripts/report_gen.py -d "$OUT/"
```

---

## Nota Penting

- Gunakan **hanya pada target dalam scope** program bug bounty
- Semak rules of engagement sebelum scan
- Jangan exceed rate limit yang ditetapkan program
- Untuk SSRF templates, ganti `{{interactsh-url}}` dengan OOB server kau sendiri:
  ```bash
  interactsh-client -server interactsh.com
  ```
- Simpan semua evidence sebelum submit report
