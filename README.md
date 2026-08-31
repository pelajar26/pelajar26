# Bug Bounty Toolkit

Automated recon & vulnerability scanning toolkit untuk mana-mana bug bounty program.

## Tools Yang Diperlukan

Install semua tools sekali gus:
```bash
chmod +x install.sh && ./install.sh
```

Tools yang akan diinstall:
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

## Cara Guna

### 1. Full Recon Pipeline
```bash
chmod +x recon.sh
./recon.sh -d example.com
```

Output akan disimpan di `output/example.com_TIMESTAMP/`:
- `subdomains_raw.txt` — semua subdomain
- `live_hosts.txt` — host yang aktif
- `httpx_full.json` — detail setiap host (status, title, tech)
- `ffuf/` — hasil directory fuzzing

### 2. Vulnerability Scan
```bash
chmod +x scripts/vuln_scan.sh
./scripts/vuln_scan.sh -l output/example.com_*/live_hosts.txt
```

Checks:
- Nuclei (CVEs, misconfigs, exposures)
- Open Redirect
- CORS Misconfiguration
- Security Headers
- Exposed sensitive files (`.env`, `.git`, backup files, dll)

### 3. JS Recon — Cari Secrets & API Endpoints
```bash
chmod +x scripts/js_recon.sh
./scripts/js_recon.sh -l output/example.com_*/live_hosts.txt
```

Extract:
- API endpoints dari JS files
- Hardcoded credentials (AWS keys, JWT, GitHub tokens, dll)
- Parameters untuk fuzzing lanjut

### 4. Generate HTML Report
```bash
python3 scripts/report_gen.py -d output/example.com_TIMESTAMP/
```

Report dalam `output/example.com_TIMESTAMP/report.html` — buka dalam browser.

## Pipeline Penuh (Satu Command)

```bash
DOMAIN="example.com"

# Step 1: Recon
./recon.sh -d $DOMAIN

# Step 2: Ambil direktori output terbaru
OUT=$(ls -td output/${DOMAIN}_* | head -1)

# Step 3: Vuln scan
./scripts/vuln_scan.sh -l $OUT/live_hosts.txt -o $OUT/vuln/

# Step 4: JS recon
./scripts/js_recon.sh -l $OUT/live_hosts.txt -o $OUT/js/

# Step 5: Generate report
python3 scripts/report_gen.py -d $OUT/
```

## Options

### recon.sh
```
-d  Target domain (required)
-o  Output directory
-w  Wordlist untuk ffuf (default: wordlists/common.txt)
-t  Threads (default: 50)
-r  Rate limit req/sec (default: 150)
-s  Skip directory fuzzing
```

### vuln_scan.sh
```
-l  Live hosts file (required)
-s  Severity: critical,high,medium,low,info
-o  Output directory
```

### js_recon.sh
```
-l  Live hosts file (required)
-o  Output directory
```

## Nota

- Gunakan **hanya pada target yang ada dalam scope** program bug bounty
- Semak rules of engagement sebelum scan
- Jangan exceed rate limit yang ditetapkan program
- Simpan semua evidence sebelum report
