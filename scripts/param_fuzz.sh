#!/usr/bin/env bash
# Parameter discovery — gabung Arjun + custom param bruteforce
# Usage: ./scripts/param_fuzz.sh -l live_hosts.txt [-p get,post]

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

HOSTS_FILE=""
METHODS="GET,POST"
OUTPUT_DIR="output/params_$(date +%Y%m%d_%H%M%S)"
THREADS=10

usage() {
    cat <<EOF
Usage: $0 -l <hosts_file> [options]

Options:
  -l  Live hosts / URLs file (required)
  -m  HTTP methods: GET,POST,JSON (default: GET,POST)
  -o  Output directory
  -t  Threads (default: 10)
  -h  Help
EOF
    exit 0
}

while getopts "l:m:o:t:h" opt; do
    case $opt in
        l) HOSTS_FILE="$OPTARG" ;;
        m) METHODS="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$HOSTS_FILE" ]] && error "Hosts file required. Use -l live_hosts.txt"
[[ ! -f "$HOSTS_FILE" ]] && error "File not found: $HOSTS_FILE"

mkdir -p "$OUTPUT_DIR"

ALL_PARAMS="$OUTPUT_DIR/all_params.txt"
INTERESTING="$OUTPUT_DIR/interesting_params.txt"
XSS_CANDIDATES="$OUTPUT_DIR/xss_candidates.txt"
SSRF_CANDIDATES="$OUTPUT_DIR/ssrf_candidates.txt"
SQLI_CANDIDATES="$OUTPUT_DIR/sqli_candidates.txt"
REDIRECT_CANDIDATES="$OUTPUT_DIR/redirect_candidates.txt"

echo "=================================================="
echo "  Parameter Discovery"
echo "  Hosts: $(wc -l < "$HOSTS_FILE") targets"
echo "  Methods: $METHODS"
echo "=================================================="

# ─── ARJUN ───────────────────────────────────────────
info "Running Arjun parameter discovery..."

if command -v arjun &>/dev/null; then
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        SAFE=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        OUT="$OUTPUT_DIR/arjun_${SAFE}.json"

        IFS=',' read -ra METHOD_LIST <<< "$METHODS"
        for method in "${METHOD_LIST[@]}"; do
            arjun \
                -u "$url" \
                -m "$method" \
                --output "$OUT" \
                -t "$THREADS" \
                -q \
                2>/dev/null && true
        done

        # Extract found params
        if [[ -f "$OUT" ]]; then
            python3 -c "
import json, sys
try:
    d = json.load(open('$OUT'))
    for url, data in d.items():
        for method, params in data.items():
            for p in params:
                print(f'{url} [{method}] {p}')
except: pass
" >> "$ALL_PARAMS" 2>/dev/null || true
        fi
    done < "$HOSTS_FILE"
    success "Arjun done. Params found: $(wc -l < "$ALL_PARAMS" 2>/dev/null || echo 0)"
else
    warn "Arjun not found. Install: pip install arjun"
fi

# ─── GAU / WAYBACK PARAM HARVEST ─────────────────────
info "Harvesting params dari URL archives..."

ARCHIVE_URLS="$OUTPUT_DIR/archive_urls.txt"

while IFS= read -r host; do
    domain=$(echo "$host" | sed 's|https\?://||' | cut -d/ -f1)

    if command -v gau &>/dev/null; then
        gau --subs "$domain" 2>/dev/null >> "$ARCHIVE_URLS" || true
    fi

    if command -v waybackurls &>/dev/null; then
        echo "$domain" | waybackurls 2>/dev/null >> "$ARCHIVE_URLS" || true
    fi
done < "$HOSTS_FILE"

# Extract unique params dari URLs
if [[ -f "$ARCHIVE_URLS" ]]; then
    sort -u "$ARCHIVE_URLS" -o "$ARCHIVE_URLS"
    ARCHIVE_COUNT=$(wc -l < "$ARCHIVE_URLS")
    success "Archive URLs found: $ARCHIVE_COUNT"

    # Extract param names
    grep -oE '\?[^#]+' "$ARCHIVE_URLS" | \
        tr '&' '\n' | \
        grep '=' | \
        cut -d= -f1 | \
        sed 's/^\?//' | \
        sort -u >> "$ALL_PARAMS" 2>/dev/null || true
fi

# Deduplicate all params
sort -u "$ALL_PARAMS" -o "$ALL_PARAMS" 2>/dev/null || true
TOTAL_PARAMS=$(wc -l < "$ALL_PARAMS" 2>/dev/null || echo 0)
success "Total unique params: $TOTAL_PARAMS"

# ─── CLASSIFY PARAMS BY VULN TYPE ────────────────────
info "Classifying parameters by vulnerability type..."

# Params yang suspicious untuk XSS
XSS_PARAMS="q|search|keyword|query|term|s|input|text|message|comment|content|html|body|data|value|name|title|label|desc|description|msg|note|post"

# Params yang suspicious untuk SSRF
SSRF_PARAMS="url|uri|link|src|source|dest|destination|redirect|return|next|callback|fetch|load|import|path|file|document|root|proxy|remote|host|domain"

# Params yang suspicious untuk SQLi
SQLI_PARAMS="id|user_id|item_id|order_id|product_id|category_id|page|limit|offset|sort|order|by|filter|search|name|username|email|phone|code|ref"

# Params untuk Open Redirect
REDIRECT_PARAMS="redirect|return|next|goto|url|link|redir|destination|dest|forward|location|target|continue|back"

grep -iE "^($XSS_PARAMS)" "$ALL_PARAMS" >> "$XSS_CANDIDATES" 2>/dev/null || true
grep -iE "^($SSRF_PARAMS)" "$ALL_PARAMS" >> "$SSRF_CANDIDATES" 2>/dev/null || true
grep -iE "^($SQLI_PARAMS)" "$ALL_PARAMS" >> "$SQLI_CANDIDATES" 2>/dev/null || true
grep -iE "^($REDIRECT_PARAMS)" "$ALL_PARAMS" >> "$REDIRECT_CANDIDATES" 2>/dev/null || true

# Mark interesting params from archive URLs
grep -E "\?.*=" "$ARCHIVE_URLS" 2>/dev/null | head -200 >> "$INTERESTING" || true

# ─── QUICK PAYLOAD TEST ──────────────────────────────
info "Testing XSS params dengan reflection check..."

XSS_REFLECTED="$OUTPUT_DIR/xss_reflected.txt"
XSS_MARKER="BBXSSTEST$(date +%s)"

if [[ -f "$ARCHIVE_URLS" ]]; then
    grep -E "\?" "$ARCHIVE_URLS" | sort -u | head -100 | while IFS= read -r url; do
        # Inject marker into each param
        modified=$(echo "$url" | sed "s/=[^&]*/=${XSS_MARKER}/g")
        response=$(curl -s --max-time 8 "$modified" 2>/dev/null || true)
        if echo "$response" | grep -q "$XSS_MARKER"; then
            echo "[XSS_REFLECTED] $modified" | tee -a "$XSS_REFLECTED"
        fi
    done
fi

REFLECTED=$(wc -l < "$XSS_REFLECTED" 2>/dev/null || echo 0)
[[ "$REFLECTED" -gt 0 ]] && success "Reflected params: $REFLECTED — POTENTIAL XSS!" || info "No reflection found in quick test"

# ─── SUMMARY ─────────────────────────────────────────
echo ""
echo "=================================================="
echo "  Parameter Discovery Complete — $OUTPUT_DIR"
echo "=================================================="
echo "  Total params      : $(wc -l < "$ALL_PARAMS" 2>/dev/null || echo 0)"
echo "  XSS candidates    : $(wc -l < "$XSS_CANDIDATES" 2>/dev/null || echo 0)"
echo "  SSRF candidates   : $(wc -l < "$SSRF_CANDIDATES" 2>/dev/null || echo 0)"
echo "  SQLi candidates   : $(wc -l < "$SQLI_CANDIDATES" 2>/dev/null || echo 0)"
echo "  Redirect candidates: $(wc -l < "$REDIRECT_CANDIDATES" 2>/dev/null || echo 0)"
echo "  Reflected params  : $(wc -l < "$XSS_REFLECTED" 2>/dev/null || echo 0)"
echo ""
echo "  Next: test payloads on candidates manually or with dalfox/sqlmap"
echo "        dalfox file $XSS_REFLECTED"
echo "=================================================="
