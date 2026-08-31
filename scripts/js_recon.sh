#!/usr/bin/env bash
# JS file recon — extract endpoints, secrets, tokens from JavaScript files
# Usage: ./scripts/js_recon.sh -l live_hosts.txt

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

HOSTS_FILE=""
OUTPUT_DIR="output/js_$(date +%Y%m%d_%H%M%S)"

usage() {
    cat <<EOF
Usage: $0 -l <hosts_file> [options]

Options:
  -l  Live hosts file (required)
  -o  Output directory
  -h  Help
EOF
    exit 0
}

while getopts "l:o:h" opt; do
    case $opt in
        l) HOSTS_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$HOSTS_FILE" ]] && error "Hosts file required. Use -l live_hosts.txt"
[[ ! -f "$HOSTS_FILE" ]] && error "File not found: $HOSTS_FILE"

mkdir -p "$OUTPUT_DIR"

JS_URLS="$OUTPUT_DIR/js_urls.txt"
ENDPOINTS="$OUTPUT_DIR/endpoints.txt"
SECRETS="$OUTPUT_DIR/potential_secrets.txt"
PARAMS="$OUTPUT_DIR/parameters.txt"

# ─── CRAWL FOR JS FILES ──────────────────────────────
info "Crawling for JavaScript files..."

if command -v katana &>/dev/null; then
    katana -list "$HOSTS_FILE" -jc -silent -o "$JS_URLS" 2>/dev/null
    grep -E "\.js(\?|$)" "$JS_URLS" > "${OUTPUT_DIR}/js_only.txt" 2>/dev/null || true
    success "JS files found: $(wc -l < "${OUTPUT_DIR}/js_only.txt" 2>/dev/null || echo 0)"
else
    warn "katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"

    # Fallback: check common JS paths
    while IFS= read -r host; do
        for js_path in "/app.js" "/main.js" "/bundle.js" "/chunk.js" "/static/js/main.*.js"; do
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${host}${js_path}" 2>/dev/null || true)
            [[ "$code" == "200" ]] && echo "${host}${js_path}" >> "$JS_URLS"
        done
    done < "$HOSTS_FILE"
fi

# ─── EXTRACT ENDPOINTS FROM JS ───────────────────────
info "Extracting API endpoints from JS files..."

JS_FILE="${OUTPUT_DIR}/js_only.txt"
[[ ! -f "$JS_FILE" ]] && JS_FILE="$JS_URLS"

while IFS= read -r js_url; do
    [[ -z "$js_url" ]] && continue
    content=$(curl -s --max-time 10 "$js_url" 2>/dev/null || true)
    [[ -z "$content" ]] && continue

    # Extract API endpoints
    echo "$content" | grep -oE '(/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+)' >> "$ENDPOINTS" 2>/dev/null || true

    # Extract potential secrets / API keys
    echo "$content" | grep -oE '(api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer|private[_-]?key|secret[_-]?key)\s*[:=]\s*["\x27][a-zA-Z0-9+/=_-]{10,}["\x27]' \
        >> "$SECRETS" 2>/dev/null || true

    # Extract parameters
    echo "$content" | grep -oE '["\x27][a-zA-Z][a-zA-Z0-9_]{2,30}["\x27]\s*:' | tr -d '"'"'" | tr -d ':' | tr -d ' ' \
        >> "$PARAMS" 2>/dev/null || true

done < "$JS_FILE"

# Deduplicate
sort -u "$ENDPOINTS" -o "$ENDPOINTS" 2>/dev/null || true
sort -u "$SECRETS" -o "$SECRETS" 2>/dev/null || true
sort -u "$PARAMS" -o "$PARAMS" 2>/dev/null || true

# ─── PATTERN MATCHING FOR SECRETS ────────────────────
info "Scanning for hardcoded credentials patterns..."

PATTERNS_OUT="$OUTPUT_DIR/pattern_matches.txt"

SECRET_PATTERNS=(
    # AWS
    'AKIA[0-9A-Z]{16}'
    'aws_secret_access_key\s*=\s*[^\s]+'
    # Google
    'AIza[0-9A-Za-z\-_]{35}'
    'ya29\.[0-9A-Za-z\-_]+'
    # Generic tokens
    'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'  # JWT
    'ghp_[a-zA-Z0-9]{36}'   # GitHub Personal Access Token
    'ghs_[a-zA-Z0-9]{36}'   # GitHub Actions Token
    'sk-[a-zA-Z0-9]{32,}'   # OpenAI / Stripe keys
    'Bearer [a-zA-Z0-9._-]{20,}'
)

while IFS= read -r js_url; do
    [[ -z "$js_url" ]] && continue
    content=$(curl -s --max-time 10 "$js_url" 2>/dev/null || true)
    for pattern in "${SECRET_PATTERNS[@]}"; do
        matches=$(echo "$content" | grep -oE "$pattern" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            echo "[PATTERN_MATCH] $js_url → $matches" | tee -a "$PATTERNS_OUT"
        fi
    done
done < "$JS_FILE"

# ─── SUMMARY ─────────────────────────────────────────
echo ""
echo "=================================================="
echo "  JS Recon Complete — $OUTPUT_DIR"
echo "=================================================="
echo "  Endpoints found    : $(wc -l < "$ENDPOINTS" 2>/dev/null || echo 0)"
echo "  Potential secrets  : $(wc -l < "$SECRETS" 2>/dev/null || echo 0)"
echo "  Pattern matches    : $(wc -l < "$PATTERNS_OUT" 2>/dev/null || echo 0)"
echo "  Unique parameters  : $(wc -l < "$PARAMS" 2>/dev/null || echo 0)"
echo "=================================================="

[[ $(wc -l < "$PATTERNS_OUT" 2>/dev/null || echo 0) -gt 0 ]] && \
    echo -e "${RED}[!] POTENTIAL SECRETS FOUND — review $PATTERNS_OUT immediately${NC}"
