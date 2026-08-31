#!/usr/bin/env bash
# Install all required bug bounty tools (requires Go 1.21+)
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

check_go() {
    if ! command -v go &>/dev/null; then
        warn "Go not found. Install from https://go.dev/dl/"
        exit 1
    fi
    ok "Go $(go version | awk '{print $3}')"
}

install_go_tool() {
    local name="$1"
    local pkg="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
    else
        info "Installing $name..."
        go install "$pkg" 2>/dev/null && ok "$name installed" || warn "Failed to install $name"
    fi
}

check_go

echo "=================================================="
echo "  Bug Bounty Toolkit — Tool Installer"
echo "=================================================="

# Recon
install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "ffuf"       "github.com/ffuf/ffuf/v2@latest"
install_go_tool "katana"     "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "dnsx"       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "naabu"      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "gau"        "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go_tool "subjack"    "github.com/haccer/subjack@latest"
install_go_tool "dalfox"     "github.com/hahwul/dalfox/v2@latest"
install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# Python tools
info "Installing Python tools..."
if command -v pip3 &>/dev/null; then
    pip3 install arjun --quiet && ok "arjun installed" || warn "Failed to install arjun"
else
    warn "pip3 not found — skip arjun"
fi

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent && ok "Nuclei templates updated"
fi

echo ""
echo "=================================================="
ok "All tools installed!"
echo "  Add to PATH: export PATH=\$PATH:\$(go env GOPATH)/bin"
echo "=================================================="
