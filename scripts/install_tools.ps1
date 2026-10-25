<#
Install the optional external tools allfinder can wrap, on Windows.
massdns / puredns do not build on Windows; allfinder uses its built-in
Python resolver there automatically.  WSL2 gives faster large brute force.
Each tool is optional: allfinder's native sources work without any of them.
#>

$ErrorActionPreference = "Continue"

function Info($m) { Write-Host "[*] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Warn "Go not found. Installing via winget ..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id GoLang.Go -e --accept-source-agreements --accept-package-agreements
        $env:Path += ";$env:ProgramFiles\Go\bin;$env:USERPROFILE\go\bin"
    } else {
        Warn "winget not available. Install Go from https://go.dev/dl/ and re-run."
        return
    }
} else {
    Info "Go found: $(go version)"
}

$gobin = if ($env:GOBIN) { $env:GOBIN } else { "$env:USERPROFILE\go\bin" }
New-Item -ItemType Directory -Force -Path $gobin | Out-Null

function Go-Install($pkg, $name) {
    if (Get-Command $name -ErrorAction SilentlyContinue) { Info "$name already installed"; return }
    Info "installing $name ..."
    go install -v "$pkg@latest" 2>$null
    if (Get-Command $name -ErrorAction SilentlyContinue) { Info "$name OK" } else { Warn "$name failed" }
}

# Tools that build cleanly on Windows
Go-Install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
Go-Install "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
Go-Install "github.com/projectdiscovery/dnsx/cmd/dnsx" "dnsx"
Go-Install "github.com/projectdiscovery/tlsx/cmd/tlsx" "tlsx"
Go-Install "github.com/projectdiscovery/alterx/cmd/alterx" "alterx"
Go-Install "github.com/projectdiscovery/asnmap/cmd/asnmap" "asnmap"
Go-Install "github.com/projectdiscovery/katana/cmd/katana" "katana"
Go-Install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" "nuclei"
Go-Install "github.com/projectdiscovery/chaos-client/cmd/chaos" "chaos"
Go-Install "github.com/owasp-amass/amass/v4/..." "amass"
Go-Install "github.com/tomnomnom/assetfinder" "assetfinder"
Go-Install "github.com/tomnomnom/unfurl" "unfurl"
Go-Install "github.com/tomnomnom/waybackurls" "waybackurls"
Go-Install "github.com/lc/gau/v2/cmd/gau" "gau"
Go-Install "github.com/hakluke/haktrails" "haktrails"
Go-Install "github.com/gwen001/github-subdomains" "github-subdomains"
Go-Install "github.com/gwen001/gitlab-subdomains" "gitlab-subdomains"
Go-Install "github.com/glebarez/cero" "cero"
Go-Install "github.com/incogbyte/shosubgo" "shosubgo"
Go-Install "github.com/Josue87/gotator" "gotator"
Go-Install "github.com/ffuf/ffuf/v2" "ffuf"

Warn "massdns / puredns are not available on Windows; the built-in Python resolver is used instead."
Warn "For large (9M) brute-force wordlists, WSL2 with massdns is much faster."
Info "done. Run 'allfinder doctor' to see what is available."
Info "Ensure $gobin is on your PATH."
