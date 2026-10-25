# allfinder

**Every subdomain finder in one place.** A terminal-only, cross-platform
subdomain enumeration engine that fuses the best passive *and* active discovery
techniques into a single `asyncio` pipeline where the stages feed each other —
normalize, resolve, filter wildcards, permute, brute-force, recurse, scrape,
probe and persist.

Built for reconnaissance in authorized security testing: bug-bounty recon,
penetration-test scoping, attack-surface monitoring and red-team asset
discovery.

> **Authorization.** Passive mode only queries third-party data and is safe to
> run against any domain. Active and probe stages send DNS and HTTP traffic to
> the target and are strictly opt-in (`--active`, `--probe`). Only run them
> against systems you are authorized to test.

---

## Why allfinder

- **72 sources, one tool.** ~45 native API/DNS sources plus wrappers for the
  heavy hitters (subfinder, amass, assetfinder, findomain, gau, cero, chaos…).
  The native pipeline needs **zero external binaries** — install and go.
- **Sources feed each other.** A name from crt.sh gets resolved; its IP seeds
  reverse DNS; its live response is scraped for more names; a parent name
  becomes a sub-root the passive sources run against again. See
  [HOW_IT_WORKS.md](HOW_IT_WORKS.md).
- **Active arsenal.** Wildcard-aware mass resolution, a permutation engine,
  wordlist brute force, AXFR + NSEC walking, SPF/SRV/CNAME record mining,
  reverse DNS, and header/HTML/JS scraping.
- **Enrichment built in.** HTTP probing (status/title/tech/CNAME/IP),
  subdomain-takeover fingerprinting, and ASN/org tagging.
- **Signal over noise.** Multi-level wildcard detection and trusted-resolver
  re-validation keep false positives out; provenance shows which source
  actually produced results for your target.
- **Operationally sane.** Per-source timeouts, concurrency and QPS limits,
  automatic API-key rotation (keys never logged), a resumable SQLite store, and
  a `diff` command for continuous monitoring.
- **Pipe-native.** `--silent` and `--json-lines` feed straight into
  `httpx`, `nuclei`, `jq` and the rest of your toolchain.
- **Windows / Linux / macOS.** A pure-Python resolver fallback means the full
  workflow runs even where `massdns`/`puredns` do not.

---

## Install

Requires **Python 3.11+**. The installer creates a virtualenv, installs
everything, and self-checks — each step prints `[ OK ]` or a clear `[FAIL]`
with the real error.

**Windows** — double-click **`install.cmd`** (add `/data` to also download
wordlists/resolvers), or:

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
```

**Linux / macOS / WSL**:

```bash
./bootstrap.sh              # add --with-data to download wordlists/resolvers
```

**Any OS, system-wide** (command on your PATH):

```bash
pipx install .              # or: uv tool install .
```

<details>
<summary>Manual install</summary>

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt   # Windows: .\.venv\Scripts\python
.venv/bin/python -m pip install -e .
```
</details>

Then, on any OS:

```bash
allfinder doctor          # which binaries / API keys / data files are present
allfinder update          # download resolvers, wordlists, takeover fingerprints
allfinder config init     # create ~/.allfinder/config.yaml for API keys
```

**New here?** The step-by-step **[SETUP.md](SETUP.md)** covers everything after
install in plain language: which API keys are worth adding and exactly where to
get them, the optional external tools, the data files, and beginner recon
recipes. None of it is required to start — the free sources work out of the box.

Optional external tools (each adds sources) install with
`scripts/install_tools.ps1` (Windows) or `scripts/install_tools.sh`
(Linux/macOS/WSL). On Windows, `massdns`/`puredns` are unavailable and the
built-in resolver is used automatically; WSL2 is faster for large brute force.

> How you invoke it depends on your install: `allfinder …` (pipx / activated
> venv), `.\.venv\Scripts\allfinder …` (Windows venv), or `.venv/bin/allfinder
> …` (Linux/macOS venv). Examples below use the bare `allfinder`.

---

## Usage

```bash
# passive recon + resolution (safe against any domain)
allfinder enum -d example.com

# full engagement pipeline: passive + active + recursion + HTTP probe
allfinder enum -d example.com --active --probe --depth 2

# multiple roots from a file
allfinder enum -l roots.txt --active --probe

# pick or drop sources (names, tags, or kinds)
allfinder enum -d example.com --use crtsh,subfinder,otx,chaos
allfinder enum -d example.com --exclude amass,searchengines

# heavy active run with limits and a time budget
allfinder enum -d example.com --active --brute large --depth 2 \
    --qps 2000 --max-time 2h

# feed the rest of your toolchain
allfinder enum -d example.com --silent | httpx -json
allfinder enum -d example.com --json-lines | jq -r 'select(.cname) | .hostname'

# inventory, diagnostics, change detection
allfinder sources [--kind passive|active|enrich] [--available]
allfinder diff -d example.com [--since <run-id>]
allfinder config set keys.shodan=KEY1,KEY2
```

**Common flags:** `-d/--domain`, `-l/--list`, `-o/--out-dir`, `--use`,
`--exclude`, `--active`, `--probe`, `--passive-only`,
`--brute {none,small,medium,large,custom:path}`, `--permute/--no-permute`,
`--depth N`, `--concurrency N`, `--qps N`, `--resolvers`,
`--trusted-resolvers`, `--timeout-per-source`, `--max-time`,
`--keep-wildcards`, `--search-engines`, `--silent`, `--json-lines`, `--proxy`,
`--resume <run-id>`, `--no-color`, `-v/-vv`.

---

## Output

Each run writes `out/<domain>/<timestamp>/`, all plain and `grep`/`jq`-friendly:

| file | contents |
|------|----------|
| `subdomains.txt` | every in-scope hostname |
| `resolved.txt` / `wildcards.txt` | resolving names / wildcard-only names |
| `alive.txt` | URLs that answered the HTTP probe |
| `related_domains.txt` | out-of-scope names found via CT / SPF / records |
| `results.json` / `.jsonl` / `.csv` | full records: sources, IPs, CNAME, HTTP, ASN, takeover |
| `sources.txt` | per-source contribution and timing |
| `run.log` | full run log (API keys redacted) |

Exit codes: `0` success, `1` usage error, `2` finished with some source
errors, `130` interrupted (partial results still written).

---

## Configuration and API keys

Copy `config.example.yaml` to `~/.allfinder/config.yaml` (or run `allfinder
config init`). Every value can also be set with an `ALLFINDER_<SECTION>__<KEY>`
environment variable, e.g. `ALLFINDER_KEYS__SHODAN=a,b`. Multiple keys per
provider rotate automatically on rate-limit/auth errors, and keys are redacted
from logs and reports. allfinder also generates subfinder's
`provider-config.yaml` from the same keys, so the wrapped subfinder shares your
credentials.

---

## How it works

The architecture, every technique, the feedback loops and the data model are
documented in **[HOW_IT_WORKS.md](HOW_IT_WORKS.md)**. In short: passive sources
run concurrently, resolution filters wildcards and confirms hits with trusted
resolvers, active techniques and recursion loop new names back into resolution,
enrichment annotates the survivors, and everything persists to a resumable,
diffable SQLite store with full per-source provenance.

Adding a source is one file — see the plugin interface in
`allfinder/plugins/base.py`. Third-party packages can register sources through
the `allfinder.plugins` entry-point group.

---

## License

MIT — see [LICENSE](LICENSE).
