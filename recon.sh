#!/usr/bin/env bash
# Full recon pipeline: subfinder → httpx → ffuf
# Usage: ./recon.sh -d example.com [-o output_dir] [-w wordlist]

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

DOMAIN=""
OUTPUT_DIR=""
WORDLIST="wordlists/common.txt"
THREADS=50
RATE=150
SKIP_FFUF=false

usage() {
    cat <<EOF
Usage: $0 -d <domain> [options]

Options:
  -d  Target domain (required)
  -o  Output directory (default: output/<domain>_<timestamp>)
  -w  Wordlist for ffuf (default: wordlists/common.txt)
  -t  Threads (default: 50)
  -r  Rate limit req/sec (default: 150)
  -s  Skip directory fuzzing
  -h  Help
EOF
    exit 0
}

while getopts "d:o:w:t:r:sh" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        r) RATE="$OPTARG" ;;
        s) SKIP_FFUF=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && error "Domain required. Use -d example.com"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-output/${DOMAIN}_${TIMESTAMP}}"
mkdir -p "$OUTPUT_DIR"

SUBDOMAINS_RAW="$OUTPUT_DIR/subdomains_raw.txt"
SUBDOMAINS_LIVE="$OUTPUT_DIR/live_hosts.txt"
HTTPX_FULL="$OUTPUT_DIR/httpx_full.json"
FFUF_DIR="$OUTPUT_DIR/ffuf"
REPORT="$OUTPUT_DIR/report.txt"

echo "=================================================="
echo "  Bug Bounty Recon - $DOMAIN"
echo "  Output: $OUTPUT_DIR"
echo "  Started: $(date)"
echo "=================================================="

# ─── PHASE 1: Subdomain Enumeration ─────────────────
info "Phase 1: Subdomain Enumeration"

if command -v subfinder &>/dev/null; then
    info "Running subfinder..."
    subfinder -d "$DOMAIN" -silent -all -recursive -o "$SUBDOMAINS_RAW" 2>/dev/null
    SUBFINDER_COUNT=$(wc -l < "$SUBDOMAINS_RAW" 2>/dev/null || echo 0)
    success "Subfinder found: $SUBFINDER_COUNT subdomains"
else
    warn "subfinder not found, skipping..."
    echo "$DOMAIN" > "$SUBDOMAINS_RAW"
fi

# Add apex domain
echo "$DOMAIN" >> "$SUBDOMAINS_RAW"

# Sort & deduplicate
sort -u "$SUBDOMAINS_RAW" -o "$SUBDOMAINS_RAW"
TOTAL_SUBS=$(wc -l < "$SUBDOMAINS_RAW")
info "Total unique subdomains: $TOTAL_SUBS"

# ─── PHASE 2: Live Host Detection ────────────────────
info "Phase 2: Live Host Detection (httpx)"

if command -v httpx &>/dev/null; then
    httpx \
        -l "$SUBDOMAINS_RAW" \
        -silent \
        -threads "$THREADS" \
        -rate-limit "$RATE" \
        -status-code \
        -title \
        -tech-detect \
        -follow-redirects \
        -json \
        -o "$HTTPX_FULL" \
        2>/dev/null | tee "$SUBDOMAINS_LIVE"

    # Extract just URLs for ffuf
    LIVE_URLS="$OUTPUT_DIR/live_urls.txt"
    if [[ -f "$HTTPX_FULL" ]]; then
        grep -o '"url":"[^"]*"' "$HTTPX_FULL" | cut -d'"' -f4 > "$LIVE_URLS" 2>/dev/null || true
    fi

    LIVE_COUNT=$(wc -l < "$SUBDOMAINS_LIVE" 2>/dev/null || echo 0)
    success "Live hosts: $LIVE_COUNT"
else
    warn "httpx not found — using subfinder output as live hosts"
    cp "$SUBDOMAINS_RAW" "$SUBDOMAINS_LIVE"
fi

# ─── PHASE 3: Directory Fuzzing ──────────────────────
if [[ "$SKIP_FFUF" = false ]]; then
    info "Phase 3: Directory Fuzzing (ffuf)"

    if command -v ffuf &>/dev/null; then
        [[ ! -f "$WORDLIST" ]] && warn "Wordlist $WORDLIST not found, skipping ffuf"

        if [[ -f "$WORDLIST" ]]; then
            mkdir -p "$FFUF_DIR"
            LIVE_URLS_FILE="${OUTPUT_DIR}/live_urls.txt"

            # Use httpx JSON output or subdomains as URLs
            if [[ ! -f "$LIVE_URLS_FILE" ]]; then
                sed 's/^/https:\/\//' "$SUBDOMAINS_LIVE" > "$LIVE_URLS_FILE" 2>/dev/null || true
            fi

            FUZZ_COUNT=0
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                SAFE_NAME=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
                OUT_FILE="$FFUF_DIR/${SAFE_NAME}.json"

                ffuf \
                    -u "${url}/FUZZ" \
                    -w "$WORDLIST" \
                    -t 40 \
                    -rate 100 \
                    -mc 200,201,204,301,302,307,401,403,405 \
                    -o "$OUT_FILE" \
                    -of json \
                    -s \
                    2>/dev/null && FUZZ_COUNT=$((FUZZ_COUNT + 1))
            done < "$LIVE_URLS_FILE"

            success "Fuzzing complete on $FUZZ_COUNT hosts"
        fi
    else
        warn "ffuf not found, skipping directory fuzzing"
    fi
fi

# ─── PHASE 4: Summary Report ─────────────────────────
info "Phase 4: Generating Summary"

cat > "$REPORT" <<REPORT_EOF
================================================
  Recon Report: $DOMAIN
  Date: $(date)
================================================

[SUBDOMAINS]
  Total found  : $TOTAL_SUBS
  File         : $SUBDOMAINS_RAW

[LIVE HOSTS]
  Total live   : $(wc -l < "$SUBDOMAINS_LIVE" 2>/dev/null || echo 0)
  File         : $SUBDOMAINS_LIVE

[HTTPX DETAILS]
  JSON output  : $HTTPX_FULL

[FFUF RESULTS]
  Directory    : $FFUF_DIR

[NEXT STEPS]
  1. Review httpx JSON for interesting tech stack
  2. Check 403 endpoints for bypass techniques
  3. Run nuclei: nuclei -l $SUBDOMAINS_LIVE -t ~/nuclei-templates/
  4. Check JS files: katana -list $SUBDOMAINS_LIVE | grep "\.js$"
  5. Parameter discovery on interesting endpoints
================================================
REPORT_EOF

cat "$REPORT"

success "Recon complete! Output saved to: $OUTPUT_DIR"
