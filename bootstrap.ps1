<#
One-command installer for allfinder on Windows.

It does EVERYTHING: finds Python, creates the .venv virtualenv, upgrades pip,
installs allfinder and its dependencies, and runs a self-check.  Every step
prints [ OK ] or a clear red [FAIL] with the real error, and the script stops
at the first failure so nothing is hidden.

Usage (from the repo root):
    powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1            # normal install
    powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -Dev       # + test tools
    powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -WithData  # + download wordlists/resolvers

Or just double-click  install.cmd  (which calls this).
#>
param(
    [switch]$Dev,
    [switch]$WithData,
    [string]$Python = ""
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$total = if ($WithData) { 6 } else { 5 }
$step = 0

function Step($msg) {
    $script:step++
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $script:step, $total, $msg) -ForegroundColor Cyan
}
function Ok($msg)   { Write-Host "      [ OK ] $msg" -ForegroundColor Green }
function Fail($msg) {
    Write-Host ""
    Write-Host "      [FAIL] $msg" -ForegroundColor Red
    Write-Host ""
    Write-Host "Installation stopped. Fix the error above and run the installer again." -ForegroundColor Red
    exit 1
}

Write-Host "=== allfinder installer (Windows) ===" -ForegroundColor White

# 1. find a Python 3.11+ interpreter --------------------------------------
Step "Looking for Python 3.11+"
$candidates = @()
if ($Python) { $candidates += $Python }
$candidates += @("python", "python3", "py")
$pyexe = $null
foreach ($c in $candidates) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    try {
        $ver = & $c -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
    } catch { continue }
    if ($ver -match '^(\d+)\.(\d+)$') {
        if ([int]$Matches[1] -gt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 11)) {
            $pyexe = $c; Ok "found $c (Python $ver)"; break
        }
    }
}
if (-not $pyexe) {
    Fail "No Python 3.11+ found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), or run:  winget install Python.Python.3.12   then re-run this installer."
}

# 2. create the virtualenv -------------------------------------------------
Step "Creating virtualenv (.venv)"
$venv = Join-Path $root ".venv"
$py = Join-Path $venv "Scripts\python.exe"
if (Test-Path $py) {
    Ok "reusing existing .venv"
} else {
    $out = & $pyexe -m venv $venv 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $py)) { Fail "could not create venv:`n$out" }
    Ok "created .venv"
}

# 3. upgrade pip -----------------------------------------------------------
Step "Upgrading pip"
$out = & $py -m pip install --upgrade pip 2>&1
if ($LASTEXITCODE -ne 0) { Fail "pip upgrade failed:`n$out" }
Ok "pip is up to date"

# 4. install allfinder + dependencies -------------------------------------
if ($Dev) { Step "Installing allfinder + test tools (this can take a minute)" }
else      { Step "Installing allfinder + dependencies (this can take a minute)" }
if ($Dev) { $out = & $py -m pip install -e ".[dev]" build 2>&1 }
else      { $out = & $py -m pip install -e . 2>&1 }
if ($LASTEXITCODE -ne 0) { Fail "dependency install failed:`n$out" }
Ok "allfinder installed"

# 5. (optional) download data files ---------------------------------------
if ($WithData) {
    Step "Downloading resolvers / wordlists / takeover fingerprints"
    $out = & $py -m allfinder update 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "      [warn] some data files could not be downloaded (you can run 'allfinder update' later):" -ForegroundColor Yellow
        Write-Host $out
    } else { Ok "data files ready" }
}

# 6. self-check ------------------------------------------------------------
Step "Verifying the installation"
$check = & $py -c "import allfinder.cli.main; from allfinder.core.registry import get_registry as g; r=g(); r.discover(); print(len(r.names()))" 2>&1
if ($LASTEXITCODE -ne 0) { Fail "allfinder does not import correctly:`n$check" }
$ver = & $py -m allfinder --version 2>&1
Ok "$ver - $check sources available"

Write-Host ""
Write-Host "=== Done. allfinder is installed. ===" -ForegroundColor Green
Write-Host ""
Write-Host "Run it (no activation needed):" -ForegroundColor White
Write-Host "    .\.venv\Scripts\allfinder doctor"
Write-Host "    .\.venv\Scripts\allfinder enum -d example.com"
if ($Dev) { Write-Host "    .\.venv\Scripts\python -m pytest -q    (run the tests)" }
Write-Host ""
