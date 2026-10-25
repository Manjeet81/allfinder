# allfinder

All the best subdomain finders in one place. A terminal-only, Python 3.11+
subdomain enumeration tool that integrates passive **and** active discovery
into one pipeline where the stages feed each other: normalize, resolve, filter
wildcards, permute, brute-force, recurse, scrape, probe and persist.

It is the spiritual successor to SubDomz (the Bash "run many tools, merge
output" script), rebuilt as an `asyncio` pipeline with provenance, a SQLite
store, resumable runs and graceful degradation when a tool or key is missing.

- **72 sources** as plugins: ~45 native (crt.sh, Cert Spotter, OTX, VirusTotal,
  SecurityTrails, Shodan, Censys, FOFA, ZoomEye, wayback, commoncrawl, GitHub,
  and more) + binary wrappers (subfinder, amass, assetfinder, findomain, gau,
  cero, chaos, …).
- **Active discovery**: wildcard-aware mass resolution, permutation engine,
  wordlist brute force, AXFR + NSEC walk, SOA/NS/MX/TXT/SPF/SRV mining,
  CNAME chains, reverse DNS, web/JS scraping.
- **Enrichment**: httpx probe (status/title/tech/CNAME/IP), subdomain-takeover
  fingerprinting, ASN/org tagging.
- **Terminal-first**: live progress table, plain output when piped,
  `--silent` and `--json-lines` for `httpx`/`jq`, plain-text + JSON + CSV files.
- **Cross-platform**: Windows, Linux and macOS. The whole native pipeline works
  with **zero external binaries** — `pipx install` already gives a useful tool.

> Active scanning sends DNS/HTTP traffic to the target. Only scan systems you
> are authorized to test. Active stages are opt-in (`--active`, `--probe`).

## Install

Requires **Python 3.11 or newer**. The whole native pipeline works with zero
external binaries, so installing the Python package alone already gives a
useful tool on every OS.

Check your Python first:

- **Windows** — `python --version` (install from <https://python.org> or
  `winget install Python.Python.3.12` if missing).
- **macOS** — `python3 --version` (`brew install python@3.12` if missing).
- **Linux** — `python3 --version` (`sudo apt install python3 python3-venv`
  on Debian/Ubuntu; use your distro's package otherwise).

The installer does everything in one step — creates the virtualenv, installs
allfinder and all dependencies, and self-checks. Each step prints `[ OK ]` or a
clear `[FAIL]` with the real error, and it stops at the first failure so
nothing is hidden.

### Windows — one click

Double-click **`install.cmd`** in the repo folder. The window stays open and
shows the result (green success or a red error). For the test tools or data
download, run it from a terminal:

```powershell
.\install.cmd            # normal install
.\install.cmd /dev       # + test tools
.\install.cmd /data      # + download resolvers/wordlists
```

(`install.cmd` just calls `bootstrap.ps1`; you can also run
`powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -Dev -WithData`.)

### Linux / macOS / WSL — one command

```bash
./bootstrap.sh              # normal install
./bootstrap.sh --dev        # + test tools
./bootstrap.sh --with-data  # + download resolvers/wordlists
```

If it is not executable yet: `chmod +x bootstrap.sh` first.

### Any OS, system-wide (pipx)

If you just want the command on your PATH without a repo checkout:

```bash
pipx install .            # from the repo root, or: uv tool install .
```

<details>
<summary>Manual install (advanced)</summary>

```bash
# Windows
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pip install -e .

# Linux / macOS / WSL
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .
```
</details>

### First run on every OS

```bash
allfinder doctor          # what binaries / keys / data files are present
allfinder update          # download resolvers, wordlists, takeover fingerprints
allfinder config init     # write ~/.allfinder/config.yaml for API keys
```

### Optional external tools (each adds more sources)

```powershell
scripts\install_tools.ps1         # Windows PowerShell (Go tools that build on Windows)
```
```bash
scripts/install_tools.sh          # Linux / macOS / WSL (Go tools, massdns, puredns, findomain)
```

On **Windows**, `massdns`/`puredns` are unavailable, so the built-in Python
resolver is used automatically; for very large brute-force wordlists, **WSL2**
with `massdns` is much faster. On **macOS/Linux** the install script needs Go
(`brew install go` / `sudo apt install golang`) for most tools.

## Usage

How you invoke it depends on whether `allfinder` is on your PATH (pipx, or an
activated venv) or you call it through the venv directly:

- **pipx / activated venv (any OS):** `allfinder ...`
- **Windows venv, not activated:** `.\.venv\Scripts\allfinder ...`
- **Linux/macOS venv, not activated:** `.venv/bin/allfinder ...`

The examples below use the bare `allfinder`; prefix it as above if needed.

```bash
allfinder enum -d example.com                      # passive + resolve + report
allfinder enum -l roots.txt --active --probe       # full pipeline
allfinder enum -d example.com --use crtsh,subfinder,otx
allfinder enum -d example.com --exclude amass,searchengines
allfinder enum -d example.com --active --brute large --depth 2 --max-time 2h
allfinder enum -d example.com --passive-only --silent | httpx
allfinder enum -d example.com --json-lines | jq .
allfinder sources [--kind passive|active|enrich] [--available]
allfinder diff -d example.com [--since <run-id>]
allfinder config init|show|set keys.shodan=abc,def
```

Piping to `httpx`/`jq` (`--silent`, `--json-lines`) works the same on every OS.
On Windows use PowerShell or `cmd`; the pipe syntax is identical.

Key flags: `-d/--domain`, `-l/--list`, `-o/--out-dir`, `--use`, `--exclude`,
`--active`, `--probe`, `--brute {none,small,medium,large,custom:path}`,
`--permute/--no-permute`, `--depth N`, `--concurrency N`, `--qps N`,
`--resolvers`, `--trusted-resolvers`, `--timeout-per-source`, `--max-time`,
`--keep-wildcards`, `--search-engines`, `--silent`, `--json-lines`, `--proxy`,
`--no-color`, `--resume <run-id>`, `-v/-vv`.

## Output

Each run writes to `out/<domain>/<timestamp>/`:

| file | contents |
|---|---|
| `subdomains.txt` | every in-scope hostname, one per line |
| `resolved.txt` / `wildcards.txt` | names that resolve / wildcard-only names |
| `alive.txt` | URLs that answered the HTTP probe |
| `related_domains.txt` | out-of-scope names found via CT / SPF / records |
| `results.json` / `.jsonl` / `.csv` | full records (sources, IPs, CNAME, HTTP, ASN, takeover) |
| `sources.txt` | per-source contribution and timing |
| `run.log` | full run log (API keys redacted) |

Exit codes: `0` ok, `1` usage error, `2` finished with some source errors,
`130` interrupted (partial results are still written).

## Configuration

Copy `config.example.yaml` to `~/.allfinder/config.yaml` (or `allfinder config
init`). Every value can also be set with an env var,
`ALLFINDER_<SECTION>__<KEY>` (e.g. `ALLFINDER_KEYS__SHODAN=a,b`). Multiple keys
per provider rotate automatically on 401/403/429. Keys are never logged.

`allfinder` also generates a subfinder `provider-config.yaml` from your key ring
automatically, so the wrapped subfinder shares the same credentials.

## Design

Everything is a plugin implementing a small async interface and discovered via
`importlib.metadata` entry points (group `allfinder.plugins`), so third-party
packages can add sources with one file. See `IMPLEMENTATION_PLAN.md` for the
full architecture.

## License

MIT — see `LICENSE`.
