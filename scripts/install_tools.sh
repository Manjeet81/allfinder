#!/usr/bin/env bash
# Install the optional external tools allfinder can wrap (Linux / macOS / WSL).
# Each tool is optional: allfinder's native sources work without any of them.
set -u

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { printf "${GREEN}[*]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$1"; }

if ! command -v go >/dev/null 2>&1; then
  warn "Go is not installed. Install it first: https://go.dev/dl/ (most tools below need it)."
else
  info "Go found: $(go version)"
fi

export GOBIN="${GOBIN:-$HOME/go/bin}"
mkdir -p "$GOBIN"

go_install() {
  local pkg="$1" name="$2"
  if command -v "$name" >/dev/null 2>&1; then
    info "$name already installed"; return
  fi
  info "installing $name ..."
  go install -v "$pkg@latest" 2>/dev/null && info "$name OK" || warn "$name failed"
}

# projectdiscovery + community tools
go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder subfinder
go_install github.com/projectdiscovery/httpx/cmd/httpx httpx
go_install github.com/projectdiscovery/dnsx/cmd/dnsx dnsx
go_install github.com/projectdiscovery/tlsx/cmd/tlsx tlsx
go_install github.com/projectdiscovery/alterx/cmd/alterx alterx
go_install github.com/projectdiscovery/asnmap/cmd/asnmap asnmap
go_install github.com/projectdiscovery/katana/cmd/katana katana
go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei nuclei
go_install github.com/projectdiscovery/naabu/v2/cmd/naabu naabu
go_install github.com/projectdiscovery/shuffledns/cmd/shuffledns shuffledns
go_install github.com/projectdiscovery/chaos-client/cmd/chaos chaos
go_install github.com/owasp-amass/amass/v4/... amass
go_install github.com/tomnomnom/assetfinder assetfinder
go_install github.com/tomnomnom/unfurl unfurl
go_install github.com/tomnomnom/waybackurls waybackurls
go_install github.com/lc/gau/v2/cmd/gau gau
go_install github.com/hakluke/haktrails haktrails
go_install github.com/hakluke/hakrevdns hakrevdns
go_install github.com/gwen001/github-subdomains github-subdomains
go_install github.com/gwen001/gitlab-subdomains gitlab-subdomains
go_install github.com/glebarez/cero cero
go_install github.com/incogbyte/shosubgo shosubgo
go_install github.com/Josue87/gotator gotator
go_install github.com/d3mondev/puredns/v2 puredns
go_install github.com/ffuf/ffuf/v2 ffuf

# massdns (needed by puredns) from source
if ! command -v massdns >/dev/null 2>&1; then
  info "building massdns from source ..."
  tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/blechschmidt/massdns "$tmp" 2>/dev/null \
     && make -C "$tmp" >/dev/null 2>&1; then
    cp "$tmp/bin/massdns" "$GOBIN/massdns" && info "massdns OK -> $GOBIN/massdns"
  else
    warn "massdns build failed (install build-essential / make)"
  fi
  rm -rf "$tmp"
fi

# findomain binary
if ! command -v findomain >/dev/null 2>&1; then
  warn "findomain: download the binary from https://github.com/Findomain/Findomain/releases"
fi

info "done. Run 'allfinder doctor' to see what is available."
info "Make sure \$GOBIN ($GOBIN) is on your PATH."
