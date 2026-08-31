#!/usr/bin/env bash
# Vulnerability scanner — runs nuclei + common manual checks
# Usage: ./scripts/vuln_scan.sh -l live_hosts.txt [-s severity]

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

HOSTS_FILE=""
SEVERITY="critical,high,medium"
OUTPUT_DIR="output/vuln_$(date +%Y%m%d_%H%M%S)"
NUCLEI_TEMPLATES="${HOME}/nuclei-templates"

usage() {
    cat <<EOF
Usage: $0 -l <hosts_file> [options]

Options:
  -l  Live hosts file (required)
  -s  Severity filter: critical,high,medium,low,info (default: critical,high,medium)
  -o  Output directory
  -t  Nuclei templates path (default: ~/nuclei-templates)
  -h  Help
EOF
    exit 0
}

while getopts "l:s:o:t:h" opt; do
    case $opt in
        l) HOSTS_FILE="$OPTARG" ;;
        s) SEVERITY="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        t) NUCLEI_TEMPLATES="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$HOSTS_FILE" ]] && error "Hosts file required. Use -l live_hosts.txt"
[[ ! -f "$HOSTS_FILE" ]] && error "File not found: $HOSTS_FILE"

mkdir -p "$OUTPUT_DIR"

echo "=================================================="
echo "  Vulnerability Scan"
echo "  Hosts: $HOSTS_FILE ($(wc -l < "$HOSTS_FILE") targets)"
echo "  Severity: $SEVERITY"
echo "=================================================="

# ─── NUCLEI ──────────────────────────────────────────
info "Running nuclei..."

if command -v nuclei &>/dev/null; then
    NUCLEI_OUT="$OUTPUT_DIR/nuclei_results.json"

    nuclei \
        -l "$HOSTS_FILE" \
        -severity "$SEVERITY" \
        -json-export "$NUCLEI_OUT" \
        -stats \
        -rate-limit 100 \
        -bulk-size 25 \
        -concurrency 25 \
        2>&1 | tee "$OUTPUT_DIR/nuclei_raw.log"

    if [[ -f "$NUCLEI_OUT" ]]; then
        TOTAL=$(wc -l < "$NUCLEI_OUT")
        success "Nuclei found $TOTAL findings → $NUCLEI_OUT"
    fi
else
    warn "nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
fi

# ─── OPEN REDIRECT CHECK ─────────────────────────────
info "Checking for Open Redirects..."

OR_OUT="$OUTPUT_DIR/open_redirect.txt"
PAYLOADS=("//evil.com" "////evil.com" "/\\evil.com" "https://evil.com" "//google.com")
PARAMS=("url" "redirect" "next" "return" "returnUrl" "return_url" "goto" "redir" "destination" "dest")

while IFS= read -r host; do
    for param in "${PARAMS[@]}"; do
        for payload in "${PAYLOADS[@]}"; do
            response=$(curl -s -o /dev/null -w "%{http_code}:%{redirect_url}" \
                --max-time 5 \
                "${host}?${param}=${payload}" 2>/dev/null || true)
            code=$(echo "$response" | cut -d: -f1)
            location=$(echo "$response" | cut -d: -f2-)
            if [[ "$code" =~ ^3 ]] && echo "$location" | grep -qi "evil.com"; then
                echo "[OPEN_REDIRECT] ${host}?${param}=${payload} → $location" | tee -a "$OR_OUT"
            fi
        done
    done
done < "$HOSTS_FILE"

OR_COUNT=$(wc -l < "$OR_OUT" 2>/dev/null || echo 0)
[[ "$OR_COUNT" -gt 0 ]] && success "Open redirects found: $OR_COUNT" || info "No open redirects found"

# ─── CORS MISCONFIGURATION ───────────────────────────
info "Checking CORS misconfigurations..."

CORS_OUT="$OUTPUT_DIR/cors_issues.txt"

while IFS= read -r host; do
    response=$(curl -s -I --max-time 5 \
        -H "Origin: https://evil.com" \
        "$host" 2>/dev/null || true)

    acao=$(echo "$response" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r')
    acac=$(echo "$response" | grep -i "Access-Control-Allow-Credentials:" | tr -d '\r')

    if echo "$acao" | grep -qi "evil.com"; then
        echo "[CORS_WILDCARD] $host → $acao $acac" | tee -a "$CORS_OUT"
    elif echo "$acao" | grep -qi "null"; then
        echo "[CORS_NULL] $host → $acao" | tee -a "$CORS_OUT"
    fi
done < "$HOSTS_FILE"

CORS_COUNT=$(wc -l < "$CORS_OUT" 2>/dev/null || echo 0)
[[ "$CORS_COUNT" -gt 0 ]] && success "CORS issues found: $CORS_COUNT" || info "No CORS issues found"

# ─── SECURITY HEADERS CHECK ──────────────────────────
info "Checking Security Headers..."

HEADERS_OUT="$OUTPUT_DIR/missing_headers.txt"
SECURITY_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "X-XSS-Protection")

while IFS= read -r host; do
    response=$(curl -s -I --max-time 5 "$host" 2>/dev/null || true)
    for header in "${SECURITY_HEADERS[@]}"; do
        if ! echo "$response" | grep -qi "$header"; then
            echo "[MISSING_HEADER] $host → $header" | tee -a "$HEADERS_OUT"
        fi
    done
done < "$HOSTS_FILE"

# ─── EXPOSED FILES CHECK ─────────────────────────────
info "Checking for exposed sensitive files..."

EXPOSED_OUT="$OUTPUT_DIR/exposed_files.txt"
SENSITIVE_PATHS=(
    "/.git/HEAD" "/.env" "/.env.local" "/.env.backup"
    "/wp-config.php" "/config.php" "/database.yml"
    "/robots.txt" "/sitemap.xml" "/.htaccess"
    "/backup.zip" "/backup.sql" "/dump.sql"
    "/phpinfo.php" "/info.php" "/test.php"
    "/admin/" "/administrator/" "/wp-admin/"
    "/.DS_Store" "/Thumbs.db"
    "/api/swagger.json" "/swagger.json" "/openapi.json"
    "/graphql" "/graphiql" "/api/graphql"
)

while IFS= read -r host; do
    for path in "${SENSITIVE_PATHS[@]}"; do
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${host}${path}" 2>/dev/null || true)
        if [[ "$code" == "200" ]]; then
            echo "[EXPOSED] ${host}${path} → HTTP $code" | tee -a "$EXPOSED_OUT"
        elif [[ "$code" == "403" ]]; then
            echo "[FORBIDDEN_BYPASS?] ${host}${path} → HTTP $code" | tee -a "$EXPOSED_OUT"
        fi
    done
done < "$HOSTS_FILE"

EXPOSED_COUNT=$(wc -l < "$EXPOSED_OUT" 2>/dev/null || echo 0)
[[ "$EXPOSED_COUNT" -gt 0 ]] && success "Exposed files/paths: $EXPOSED_COUNT" || info "No obvious exposed files"

# ─── SUMMARY ─────────────────────────────────────────
echo ""
echo "=================================================="
echo "  Scan Complete — Results in: $OUTPUT_DIR"
echo "=================================================="
echo "  Open Redirects  : $(wc -l < "$OR_OUT" 2>/dev/null || echo 0)"
echo "  CORS Issues     : $(wc -l < "$CORS_OUT" 2>/dev/null || echo 0)"
echo "  Exposed Files   : $(wc -l < "$EXPOSED_OUT" 2>/dev/null || echo 0)"
echo "=================================================="
