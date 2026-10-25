#!/usr/bin/env bash
# One-command installer for allfinder on Linux / macOS / WSL.
#
# It does EVERYTHING: finds Python, creates the .venv virtualenv, upgrades pip,
# installs allfinder and its dependencies, and runs a self-check.  Every step
# prints [ OK ] or a clear red [FAIL] with the real error, and the script stops
# at the first failure so nothing is hidden.
#
# Usage (from the repo root):
#   ./bootstrap.sh              # normal install
#   ./bootstrap.sh --dev        # + test tools
#   ./bootstrap.sh --with-data  # + download wordlists/resolvers
#   (flags can be combined)

cd "$(dirname "$0")" || exit 1

DEV=0
WITH_DATA=0
for arg in "$@"; do
  case "$arg" in
    --dev) DEV=1 ;;
    --with-data) WITH_DATA=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; C=$'\033[36m'; Y=$'\033[33m'; N=$'\033[0m'; else R= G= C= Y= N=; fi
TOTAL=5; [ "$WITH_DATA" = 1 ] && TOTAL=6
STEP=0

step() { STEP=$((STEP+1)); printf "\n${C}[%d/%d] %s${N}\n" "$STEP" "$TOTAL" "$1"; }
ok()   { printf "      ${G}[ OK ]${N} %s\n" "$1"; }
fail() {
  printf "\n      ${R}[FAIL] %s${N}\n\n" "$1"
  printf "${R}Installation stopped. Fix the error above and run the installer again.${N}\n"
  exit 1
}

echo "=== allfinder installer (Linux/macOS/WSL) ==="

# 1. find Python 3.11+ -----------------------------------------------------
step "Looking for Python 3.11+"
PYEXE=""
for c in "${PYTHON:-}" python3 python; do
  [ -z "$c" ] && continue
  command -v "$c" >/dev/null 2>&1 || continue
  ver="$("$c" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" || continue
  maj="${ver%%.*}"; min="${ver#*.}"
  if [ "$maj" -gt 3 ] 2>/dev/null || { [ "$maj" = 3 ] && [ "$min" -ge 11 ] 2>/dev/null; }; then
    PYEXE="$c"; ok "found $c (Python $ver)"; break
  fi
done
[ -z "$PYEXE" ] && fail "No Python 3.11+ found. Install it:  Debian/Ubuntu 'sudo apt install python3 python3-venv' | macOS 'brew install python@3.12'  then re-run."

# 2. create venv -----------------------------------------------------------
# venv layout differs: POSIX uses bin/, Windows (git-bash) uses Scripts/.
venv_py() {
  for p in .venv/bin/python .venv/bin/python3 .venv/Scripts/python.exe .venv/Scripts/python; do
    [ -x "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}
step "Creating virtualenv (.venv)"
if PY="$(venv_py)"; then
  ok "reusing existing .venv"
else
  out="$("$PYEXE" -m venv .venv 2>&1)" || fail "could not create venv:
$out"
  PY="$(venv_py)" || fail "venv created but no python inside it (on Debian/Ubuntu install python3-venv):
$out"
  ok "created .venv"
fi

# 3. upgrade pip -----------------------------------------------------------
step "Upgrading pip"
out="$("$PY" -m pip install --upgrade pip 2>&1)" || fail "pip upgrade failed:
$out"
ok "pip is up to date"

# 4. install allfinder -----------------------------------------------------
if [ "$DEV" = 1 ]; then
  step "Installing allfinder + test tools (this can take a minute)"
  out="$("$PY" -m pip install -e ".[dev]" build 2>&1)" || fail "dependency install failed:
$out"
else
  step "Installing allfinder + dependencies (this can take a minute)"
  out="$("$PY" -m pip install -e . 2>&1)" || fail "dependency install failed:
$out"
fi
ok "allfinder installed"

# 5. optional data download ------------------------------------------------
if [ "$WITH_DATA" = 1 ]; then
  step "Downloading resolvers / wordlists / takeover fingerprints"
  if out="$("$PY" -m allfinder update 2>&1)"; then
    ok "data files ready"
  else
    printf "      ${Y}[warn] some data files could not be downloaded (run 'allfinder update' later):${N}\n%s\n" "$out"
  fi
fi

# 6. self-check ------------------------------------------------------------
step "Verifying the installation"
check="$("$PY" -c 'import allfinder.cli.main; from allfinder.core.registry import get_registry as g; r=g(); r.discover(); print(len(r.names()))' 2>&1)" \
  || fail "allfinder does not import correctly:
$check"
ver="$("$PY" -m allfinder --version 2>&1)"
ok "$ver - $check sources available"

printf "\n${G}=== Done. allfinder is installed. ===${N}\n\n"
echo "Run it (no activation needed):"
echo "    .venv/bin/allfinder doctor"
echo "    .venv/bin/allfinder enum -d example.com"
[ "$DEV" = 1 ] && echo "    .venv/bin/python -m pytest -q    (run the tests)"
echo
