#!/usr/bin/env bash
# Subdomain Takeover detection
# Usage: ./scripts/subdomain_takeover.sh -l subdomains.txt

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
vuln()    { echo -e "${RED}[VULNERABLE]${NC} $*"; }

SUBDOMAINS_FILE=""
OUTPUT_DIR="output/takeover_$(date +%Y%m%d_%H%M%S)"
THREADS=20

usage() {
    cat <<EOF
Usage: $0 -l <subdomains_file> [options]

Options:
  -l  Subdomains file (required)
  -o  Output directory
  -t  Threads (default: 20)
  -h  Help
EOF
    exit 0
}

while getopts "l:o:t:h" opt; do
    case $opt in
        l) SUBDOMAINS_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$SUBDOMAINS_FILE" ]] && { echo "Use -l subdomains.txt"; exit 1; }
[[ ! -f "$SUBDOMAINS_FILE" ]] && { echo "File not found: $SUBDOMAINS_FILE"; exit 1; }

mkdir -p "$OUTPUT_DIR"

VULNERABLE="$OUTPUT_DIR/vulnerable.txt"
DANGLING_CNAME="$OUTPUT_DIR/dangling_cname.txt"
NXDOMAIN="$OUTPUT_DIR/nxdomain.txt"
UNCLAIMED="$OUTPUT_DIR/unclaimed_services.txt"

echo "=================================================="
echo "  Subdomain Takeover Detection"
echo "  Subdomains: $(wc -l < "$SUBDOMAINS_FILE")"
echo "=================================================="

# ─── SUBJACK / NUCLEI ────────────────────────────────
info "Checking with nuclei subdomain-takeover templates..."

if command -v nuclei &>/dev/null; then
    nuclei \
        -l "$SUBDOMAINS_FILE" \
        -t "~/nuclei-templates/http/takeovers/" \
        -severity "high,critical" \
        -silent \
        -json \
        -o "$OUTPUT_DIR/nuclei_takeover.json" \
        2>/dev/null && true

    COUNT=$(wc -l < "$OUTPUT_DIR/nuclei_takeover.json" 2>/dev/null || echo 0)
    [[ "$COUNT" -gt 0 ]] && success "Nuclei takeover findings: $COUNT"
fi

if command -v subjack &>/dev/null; then
    info "Running subjack..."
    subjack \
        -w "$SUBDOMAINS_FILE" \
        -t "$THREADS" \
        -o "$OUTPUT_DIR/subjack.txt" \
        -ssl \
        2>/dev/null && true
    success "Subjack done → $OUTPUT_DIR/subjack.txt"
fi

# ─── FINGERPRINT DATABASE ────────────────────────────
# Known service fingerprints for takeover detection
declare -A SERVICE_FINGERPRINTS=(
    # Service = "CNAME pattern|Error page fingerprint"
    ["GitHub Pages"]="github.io|There isn't a GitHub Pages site here"
    ["Heroku"]="herokudns.com|herokuapp.com|No such app"
    ["Shopify"]="myshopify.com|Sorry, this shop is currently unavailable"
    ["Fastly"]="fastly.net|Fastly error: unknown domain"
    ["Ghost"]="ghost.io|The thing you were looking for is no longer here"
    ["Tumblr"]="tumblr.com|There's nothing here"
    ["WordPress"]="wordpress.com|Do you want to register"
    ["Desk"]="desk.com|Please try again or try Desk.com free for"
    ["Zendesk"]="zendesk.com|Help Center Closed"
    ["Unbounce"]="unbouncepages.com|The requested URL was not found"
    ["HubSpot"]="hubspot.net|Domain not configured"
    ["Surge"]="surge.sh|project not found"
    ["Bitbucket"]="bitbucket.io|Repository not found"
    ["UserVoice"]="uservoice.com|This UserVoice subdomain is currently available"
    ["Pingdom"]="stats.pingdom.com|This public report page has not been activated"
    ["Tave"]="tave.com|This page is no longer active"
    ["Teamwork"]="teamwork.com|Oops - We didn't find your site"
    ["Helpjuice"]="helpjuice.com|We could not find what you're looking for"
    ["S3 AWS"]="amazonaws.com|NoSuchBucket|The specified bucket does not exist"
    ["Cargo"]="cargocollective.com|If you're moving your domain away from Cargo"
    ["StatusPage"]="statuspage.io|You are being redirected"
    ["Campaign Monitor"]="createsend.com|Double check the URL"
    ["Acquia"]="acquia-sites.com|The site you are looking for could not be found"
    ["ReadMe"]="readme.io|Project doesnt exist"
    ["Fly.io"]="fly.dev|fly.io|404 - No app found"
    ["Render"]="onrender.com|service not found"
)

# ─── MANUAL CNAME + CONTENT CHECK ───────────────────
info "Checking CNAME records and service fingerprints..."

check_subdomain() {
    local sub="$1"

    # Get CNAME
    local cname
    cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1 | sed 's/\.$//' || true)

    # Get A record
    local a_record
    a_record=$(dig +short A "$sub" 2>/dev/null | head -1 || true)

    # NXDOMAIN check
    local nxdomain
    nxdomain=$(dig +short "$sub" 2>/dev/null || true)
    if [[ -z "$nxdomain" && -z "$cname" ]]; then
        echo "$sub" >> "$NXDOMAIN"
        return
    fi

    # Check CNAME against service fingerprints
    for service in "${!SERVICE_FINGERPRINTS[@]}"; do
        IFS='|' read -ra parts <<< "${SERVICE_FINGERPRINTS[$service]}"
        local cname_pattern="${parts[0]}"
        local content_pattern="${parts[1]}"

        if [[ -n "$cname" ]] && echo "$cname" | grep -qi "$cname_pattern"; then
            echo "$sub → CNAME: $cname" >> "$DANGLING_CNAME"

            # Fetch page content to confirm
            local content
            content=$(curl -s --max-time 8 -L "https://${sub}" 2>/dev/null || \
                      curl -s --max-time 8 -L "http://${sub}" 2>/dev/null || true)

            if [[ -n "$content_pattern" ]] && echo "$content" | grep -qi "$content_pattern"; then
                vuln "$sub [$service] → CNAME: $cname"
                echo "[VULNERABLE] $sub [$service] → $cname" >> "$VULNERABLE"
                echo "[VULNERABLE] $sub [$service] → $cname" >> "$UNCLAIMED"
            fi
        fi
    done
}

export -f check_subdomain
export DANGLING_CNAME NXDOMAIN VULNERABLE UNCLAIMED

# Run in parallel using xargs
if command -v parallel &>/dev/null; then
    parallel -j "$THREADS" check_subdomain :::: "$SUBDOMAINS_FILE"
else
    # Fallback: background jobs with simple concurrency
    RUNNING=0
    while IFS= read -r sub; do
        check_subdomain "$sub" &
        RUNNING=$((RUNNING + 1))
        if [[ "$RUNNING" -ge "$THREADS" ]]; then
            wait
            RUNNING=0
        fi
    done < "$SUBDOMAINS_FILE"
    wait
fi

# ─── S3 BUCKET CHECK ─────────────────────────────────
info "Checking S3 bucket misconfigurations..."

S3_VULN="$OUTPUT_DIR/s3_issues.txt"

while IFS= read -r sub; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1 || true)

    if echo "$cname" | grep -qi "amazonaws.com\|s3"; then
        bucket_name=$(echo "$cname" | grep -oE '[a-z0-9-]+\.s3' | cut -d. -f1)

        # Check if bucket exists and is listable
        response=$(curl -s --max-time 8 "https://${cname}/" 2>/dev/null || true)

        if echo "$response" | grep -qi "NoSuchBucket\|The specified bucket does not exist"; then
            echo "[S3_UNCLAIMED] $sub → $cname (bucket doesn't exist — claimable!)" | tee -a "$S3_VULN" "$VULNERABLE"
        elif echo "$response" | grep -qi "ListBucketResult"; then
            echo "[S3_LISTING_ON] $sub → $cname (bucket listing enabled!)" | tee -a "$S3_VULN"
        fi
    fi
done < "$SUBDOMAINS_FILE"

# ─── SUMMARY ─────────────────────────────────────────
echo ""
echo "=================================================="
echo "  Subdomain Takeover Scan Complete — $OUTPUT_DIR"
echo "=================================================="
echo "  NXDOMAIN subdomains  : $(wc -l < "$NXDOMAIN" 2>/dev/null || echo 0)"
echo "  Dangling CNAMEs      : $(wc -l < "$DANGLING_CNAME" 2>/dev/null || echo 0)"
echo "  VULNERABLE (takeover): $(wc -l < "$VULNERABLE" 2>/dev/null || echo 0)"
echo "  S3 issues            : $(wc -l < "$S3_VULN" 2>/dev/null || echo 0)"
echo "=================================================="

if [[ $(wc -l < "$VULNERABLE" 2>/dev/null || echo 0) -gt 0 ]]; then
    echo ""
    vuln "VULNERABLE SUBDOMAINS:"
    cat "$VULNERABLE"
fi
