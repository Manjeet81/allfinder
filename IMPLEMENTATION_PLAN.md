# allfinder — Implementation Plan

**Goal:** A Python 3.11+ **terminal-only** subdomain-enumeration tool that integrates the best passive *and* active discovery techniques in the world into one pipeline, where tools **feed each other** instead of just running side by side. SubDomz (Bash) is the reference for "run many tools, merge output"; allfinder goes further: normalize, resolve, filter wildcards, permute, brute-force, recurse, scrape, probe, and persist.

**Terminal-only means:** you run `allfinder` in a shell, progress and results print to the terminal, and output is written to plain text/JSON/CSV files. There is no web UI, no HTML report, no screenshots, no webhooks, no Docker image. It runs directly on Windows, Linux and macOS from the user's own terminal.

---

## 0. What SubDomz does, and what we keep / fix

| SubDomz behaviour | Keep? | allfinder change |
|---|---|---|
| 19 passive sources (subfinder, amass, assetfinder, chaos, findomain, haktrails, gau, github/gitlab-subdomains, cero, shosubgo, censys, crt.sh, anubis, OTX, subdomain.center, certspotter, VirusTotal) | Yes | All of them + ~40 more, as plugins |
| puredns brute force | Yes | Full active stage: brute, permutation, zone transfer, cert scan, reverse DNS, web scrape, recursion |
| GNU `parallel -j18` | Replace | `asyncio` task groups with per-source concurrency limits and timeouts |
| `tmp-*` files + `sort -u` | Replace | In-memory normalized set + SQLite store with per-source provenance |
| `-u/-e` incompatible with `-p` | Fix | Any source selection works with any concurrency |
| `config.txt` shell exports | Replace | `config.yaml` + env vars + per-provider key rotation |
| `-hp` httpx probe | Keep | Probe stage with JSON output (status, title, tech, CNAME, IP) |
| Linux-only (`parallel`, massdns) | Fix | Runs from the terminal on Windows/Linux/macOS; pure-Python fallback resolver where massdns is unavailable |
| Bugs: Puredns writes to `tmp-certspotter`, uses `$DOMAIN` not `$domain`, Gitlab prints "Github" | n/a | Tests per plugin |

---

## 1. Design principles

1. **Everything is a plugin.** Each source/technique is one Python module implementing a small interface. Adding a new source = one file + one test.
2. **Native first, wrapper second.** APIs that are simple HTTP calls (crt.sh, OTX, certspotter, hackertarget, …) are implemented natively in Python with `httpx`. Heavy tools (subfinder, amass, massdns/puredns, httpx, nuclei) are wrapped as external binaries because re-implementing them is wasteful.
3. **Pipeline with feedback loops.** New subdomains discovered in a later stage are fed back to earlier stages (bounded recursion depth) so the stages "work together".
4. **Provenance everywhere.** Every subdomain records which sources found it, when, resolved IPs, CNAME, wildcard status, HTTP status. This enables "which source is actually valuable for this target" reports.
5. **Graceful degradation.** Missing binary or API key → plugin is skipped with a one-line warning, never a crash. `allfinder doctor` tells the user what's missing.
6. **Resumable.** Long runs (brute force on 9M wordlist) persist state; `--resume` continues.
7. **Scope-aware / ethical.** Active stages only run when the user opts in (`--active`), with rate limits, and a clear notice that active scanning must be authorized.
8. **Terminal is the only interface.** Every feature is reachable from CLI flags; every result is readable with `cat`, `grep`, and `jq`; `--silent` makes it pipe-friendly (`allfinder enum -d x.com --silent | httpx`). No servers, no browsers, no GUIs.

---

## 2. Architecture

```
                         ┌───────────────────────────────┐
                         │          CLI (typer)          │
                         │ allfinder enum -d example.com │
                         └───────────────┬───────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │   Orchestrator / Pipeline       │
                        │   (asyncio, stage scheduler)    │
                        └────────────────┬────────────────┘
          ┌──────────────┬───────────────┼───────────────┬─────────────────┐
          ▼              ▼               ▼               ▼                 ▼
   ┌─────────────┐ ┌───────────┐ ┌─────────────┐ ┌──────────────┐ ┌──────────────┐
   │ 1. PASSIVE  │ │2. RESOLVE │ │ 3. ACTIVE   │ │ 4. RECURSE   │ │ 5. PROBE &   │
   │  ~60 srcs   │ │ massdns / │ │ brute/perm/ │ │ re-run 1-3   │ │   ENRICH     │
   │ API+binary  │ │ aiodns    │ │ axfr/cert/  │ │ on new hits  │ │ httpx,tlsx,  │
   │             │ │ wildcard  │ │ rdns/scrape │ │ depth-limited│ │ takeover,    │
   └──────┬──────┘ └─────┬─────┘ └──────┬──────┘ └──────┬───────┘ └──────┬───────┘
          └──────────────┴──────────────┴────────────────┴────────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │   Result Store (SQLite + model) │
                        │   subdomain, sources[], ips[],  │
                        │   cname, wildcard, http, ts     │
                        └────────────────┬────────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │   Reporters: txt/json/csv       │
                        │   stdout stream, diff vs last   │
                        └─────────────────────────────────┘
```

### 2.1 Pipeline stages (default order)

| # | Stage | What runs | Input | Output |
|---|---|---|---|---|
| 1 | **passive** | all passive plugins concurrently | root domain | candidate names |
| 2 | **resolve** | wildcard detection → mass resolution → filter | candidates | resolved + unresolved |
| 3 | **active** | brute force, permutations, AXFR, NSEC walk, cert scanning, reverse DNS, web scrape (CSP/JS/robots/sitemap), VHost | root + resolved | more candidates → back to stage 2 |
| 4 | **recurse** | run passive(+permute) on each *new* resolved subdomain that has its own sub-level (e.g. `dev.api.example.com` → treat `api.example.com` as a root), depth ≤ N | new subs | more candidates → stage 2 |
| 5 | **probe/enrich** | httpx (status/title/tech), tlsx (SAN harvest → feedback), CNAME takeover check, ASN/IP enrichment | resolved subs | enriched records |
| 6 | **report** | writers | store | files |

Stages 3–5 are opt-in (`--active`, `--probe`); stage 1–2 and 6 always run. Loop 2→3→2 and 2→4→2 are bounded by `--depth` (default 1) and `--max-new-per-round`.

### 2.2 Plugin interface

```python
# allfinder/plugins/base.py
class SourceKind(enum.Enum):
    PASSIVE = "passive"       # no packets to target
    ACTIVE = "active"         # touches target DNS / HTTP
    ENRICH = "enrich"         # adds data to existing subs

class Requirement(TypedDict, total=False):
    binaries: list[str]       # e.g. ["subfinder"]
    api_keys: list[str]       # e.g. ["SECURITYTRAILS_KEY"]
    files: list[str]          # e.g. ["resolvers", "wordlist"]

class Plugin(abc.ABC):
    name: str                 # "crtsh"
    kind: SourceKind
    requires: Requirement = {}
    default_timeout: int = 120
    rate_limit: float | None  # requests/sec (passive APIs)
    weight: int = 1           # ordering/priority hint

    @abc.abstractmethod
    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        ...

@dataclass(slots=True)
class Finding:
    hostname: str             # normalized, lowercase, no trailing dot, no wildcard
    source: str
    ips: list[str] = field(default_factory=list)   # optional pre-resolved data
    cname: str | None = None
    extra: dict = field(default_factory=dict)       # raw API data
```

`RunContext` gives plugins: `http` (shared `httpx.AsyncClient` with retries + proxy), `keys` (key ring with rotation), `binaries` (path resolver), `limiter` (per-host token bucket), `store`, `logger`, `tmpdir`, `cancel` token.

Plugins are discovered via `importlib.metadata` entry points (`allfinder.plugins`) so third-party packages can add sources.

### 2.3 Data model (SQLite via `sqlite3` + thin DAO, or SQLModel)

```
targets(id, root_domain, created_at)
runs(id, target_id, started_at, finished_at, args_json, version)
subdomains(id, target_id, hostname UNIQUE, first_seen_run, last_seen_run,
           resolved BOOL, wildcard BOOL, cname, ips_json, asn, org,
           http_status, http_title, http_tech_json, takeover_json)
findings(id, run_id, subdomain_id, source, ts)          -- provenance, many-to-many
source_stats(run_id, source, count_total, count_unique, duration_s, error)
```

Diff between runs (`allfinder diff`) is a plain query: hostnames whose `first_seen_run == latest`.

---

## 3. Source catalogue

Legend: **N** = native Python (httpx/dns), **B** = wraps external binary, 🔑 = needs API key, 🆓 = free.

### 3.1 Passive — certificate transparency
| Source | Impl | Key |
|---|---|---|
| crt.sh (JSON + direct Postgres `crt.sh:5432` for big domains) | N | 🆓 |
| CertSpotter | N | 🆓 (key raises limits) |
| Censys Search (certs + hosts) | N | 🔑 |
| Google CT / Facebook CT API | N | 🔑 (FB) |
| Cero (TLS SAN scrape of IP ranges) | B | 🆓 |
| tlsx (projectdiscovery; SAN/CN from resolved IPs) | B | 🆓 |

### 3.2 Passive — threat intel / DNS datasets
| Source | Impl | Key |
|---|---|---|
| AlienVault OTX (passive_dns + url_list, paginated) | N | 🆓 |
| VirusTotal v3 `/domains/{d}/subdomains` (paginated) | N | 🔑 |
| SecurityTrails (also via haktrails) | N | 🔑 |
| Shodan (`dns/domain`) + shosubgo | N | 🔑 |
| FOFA | N | 🔑 |
| ZoomEye | N | 🔑 |
| Hunter.how | N | 🔑 |
| Netlas | N | 🔑 |
| Quake (360) | N | 🔑 |
| BinaryEdge | N | 🔑 |
| FullHunt | N | 🔑 |
| LeakIX | N | 🔑 |
| Chaos (projectdiscovery) | N | 🔑 |
| PassiveTotal / Defender TI | N | 🔑 |
| WhoisXMLAPI subdomains | N | 🔑 |
| C99 subdomain finder | N | 🔑 |
| DNSDB (Farsight) | N | 🔑 |
| BeVigil (mobile app OSINT) | N | 🔑 |
| RedHunt Labs | N | 🔑 |
| CriminalIP | N | 🔑 |
| Digitorus | N | 🆓 |
| HackerTarget hostsearch | N | 🆓 |
| RapidDNS | N | 🆓 |
| DNSDumpster (new API) | N | 🔑/🆓 |
| ThreatMiner | N | 🆓 |
| Riddler | N | 🆓 |
| Robtex | N | 🆓 |
| SiteDossier | N | 🆓 |
| Anubis (jldc.me) | N | 🆓 |
| subdomain.center | N | 🆓 |
| Columbus (columbus.elmasy.com) | N | 🆓 |
| ShrewdEye | N | 🆓 |
| Netcraft (HTML scrape) | N | 🆓 |
| DNSRepo | N | 🆓 |
| Chinaz / ip138 / Baidu CE | N | 🆓 |
| ThreatBook | N | 🔑 |

### 3.3 Passive — web archives & URL datasets
| Source | Impl | Key |
|---|---|---|
| Wayback CDX (`web.archive.org/cdx/search`) | N | 🆓 |
| CommonCrawl index | N | 🆓 |
| urlscan.io search | N | 🆓/🔑 |
| gau (wraps wayback+cc+otx+urlscan) → `unfurl domains` | B | 🆓 |
| waybackurls | B | 🆓 |

### 3.4 Passive — code search
| Source | Impl | Key |
|---|---|---|
| GitHub code search (github-subdomains) | B/N | 🔑 |
| GitLab (gitlab-subdomains) | B | 🔑 |
| grep.app | N | 🆓 |
| Bitbucket (optional) | N | 🆓 |

### 3.5 Passive — search engines (dork scraping, low yield, rate-limited)
Google, Bing, Yahoo, DuckDuckGo, Baidu, Yandex, Ask, Sogou, So360 — **N**, behind `--search-engines` flag with backoff; Bing API key if available.

### 3.6 Passive — aggregator binaries (each is itself many sources)
| Tool | Notes |
|---|---|
| subfinder `-all -silent -json` | reads `provider-config.yaml`; we generate it from our config |
| amass `enum -passive` (v4/v5 output differs → parse `-json`/`-oA`) | |
| assetfinder `--subs-only` | |
| findomain `-q` | |
| Sublist3r / OneForAll / Subdominator / sudomy (python; optional, `pip extra`) | import or subprocess |
| bbot `-f subdomain-enum` (optional heavy mode) | JSON events |
| theHarvester `-b all` | |

### 3.7 Active — DNS
| Technique | Impl |
|---|---|
| **Wildcard detection** (N random labels, per level, collect wildcard IP sets) | N (aiodns) |
| **Mass resolution** with resolver pool, retries, wildcard filtering | B (`puredns resolve` / `massdns`) with **N fallback** (`aiodns` + semaphore, ~2–5k qps) |
| **Brute force** wordlists: assetnote `best-dns-wordlist`, `2m-subdomains`, n0kovo, SecLists, jhaddix all.txt; size tiers `--brute small/medium/large` | B (`puredns bruteforce`, `shuffledns`) / N fallback |
| **Permutation / alteration**: alterx, gotator, dnsgen, altdns, ripgen, regulator-style pattern mining from already-found names | B + **N** (own permutation engine: prefixes/suffixes/numbers/env words/dash-dot swaps) |
| **Zone transfer (AXFR)** on every NS | N (dnspython) |
| **NSEC / NSEC3 walking** (DNSSEC zones) | N (dnspython) + `ldns-walk` if present |
| **Reverse DNS (PTR)** over all resolved IPs' /24 and ASN ranges | N + dnsx `-ptr` / hakrevdns |
| **SRV / TXT / MX / SPF / DMARC record mining** (spf `include:` reveals hosts) | N |
| **CNAME chain following** (reveals third-party + internal names) | N |
| Resolver list: trickest/resolvers auto-download + `dnsvalidator` refresh | N |

### 3.8 Active — network / cert
| Technique | Impl |
|---|---|
| ASN → CIDR (asnmap, bgp.he.net, ipinfo) → cert scan (tlsx / cero) | B/N |
| Favicon-hash & cert-hash pivot in Shodan/Censys/FOFA | N |
| VHost brute force on resolved IPs (Host header fuzz) | B (ffuf) / N |

### 3.9 Active — web scraping of discovered hosts (feedback loop)
| Technique | Impl |
|---|---|
| CSP headers, `Access-Control-Allow-Origin`, `Link`, redirects | N |
| JS file scraping for `*.example.com` strings (subjs/linkfinder-style regex) | N / katana `-jc` |
| robots.txt, sitemap.xml, security.txt, `.well-known/` | N |
| HTML `href/src` harvesting (shallow crawl, depth 1) | N / katana |
| TLS cert SANs of every live host (tlsx) | B |

### 3.10 Enrichment / post-processing
| Technique | Impl |
|---|---|
| HTTP probe: status, title, tech, content-length, redirect chain, IP, CDN | B (httpx `-json`) with N fallback |
| Subdomain takeover check (CNAME fingerprint db: `can-i-take-over-xyz`, + nuclei `-t takeovers`, subzy, dnsReaper) | N + B |
| IP → ASN/org/CDN tagging (ipinfo/ipapi/mmdb) | N |
| Port scan of resolved IPs (naabu) — optional, text output only | B |

---

## 4. Technology stack

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | `asyncio.TaskGroup`, `ExceptionGroup`, speed |
| CLI | `typer` + `rich` | sub-commands; `rich` is used only for terminal colour and a live per-source progress table (falls back to plain lines with `--no-color` or when stdout is not a TTY) |
| HTTP | `httpx[http2]` async + `tenacity` retries | shared client, proxies, HTTP/2 |
| DNS | `dnspython` (AXFR, NSEC, records) + `aiodns`/`pycares` (bulk resolve) | |
| Config | `pydantic-settings` + YAML (`config.yaml`), env override `ALLFINDER_*` | validation, key rotation lists |
| Storage | SQLite (`aiosqlite`) | zero-dep, resumable, diffable |
| Subprocess | `asyncio.create_subprocess_exec` with streaming stdout parsing, timeouts, kill on cancel | |
| Packaging | `pyproject.toml` (hatch/uv), `pipx install allfinder` or `uv tool install .`, console script `allfinder` | |
| Lint/test | `ruff`, `mypy --strict`, `pytest` + `pytest-asyncio` + `respx` (HTTP mocks) | |
| Docs | `README.md`, `allfinder sources` prints the source list in the terminal (no separate docs site) | |

---

## 5. Repository layout

```
allfinder/
├── pyproject.toml
├── README.md
├── IMPLEMENTATION_PLAN.md
├── config.example.yaml
├── scripts/
│   ├── install_tools.sh          # Go tools, massdns, puredns, findomain
│   ├── install_tools.ps1         # Windows (Go tools that build on Windows)
│   └── update_wordlists.py       # resolvers + wordlists download/refresh
├── data/                         # downloaded at runtime into ~/.allfinder/data
│   └── takeover_fingerprints.json
├── allfinder/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli/
│   │   ├── main.py               # typer app: enum, doctor, sources, diff, resume, config
│   │   └── ui.py                 # rich live table (source | status | found | unique | time)
│   ├── core/
│   │   ├── config.py             # pydantic settings, YAML loader, key ring
│   │   ├── context.py            # RunContext
│   │   ├── models.py             # Finding, Subdomain, Target dataclasses
│   │   ├── normalize.py          # lowercase, strip *., trailing dot, punycode, validity regex, in-scope check
│   │   ├── pipeline.py           # stage scheduler + feedback loops
│   │   ├── registry.py           # plugin discovery (entry points + builtin)
│   │   ├── runner.py             # run N plugins concurrently with per-plugin timeout/semaphore
│   │   ├── store.py              # SQLite DAO
│   │   ├── binaries.py           # which(), version check, install hints
│   │   ├── http.py               # shared AsyncClient, rate limiter, retries, UA rotation
│   │   ├── dns/
│   │   │   ├── resolver_pool.py  # load/validate resolvers, round-robin
│   │   │   ├── wildcard.py       # multi-level wildcard detection & filtering
│   │   │   ├── massresolve.py    # puredns/massdns wrapper + aiodns fallback
│   │   │   └── records.py        # AXFR, NSEC walk, MX/TXT/SRV/SPF mining, PTR
│   │   └── wordlists.py          # tiered wordlists, downloader, cache
│   ├── plugins/
│   │   ├── base.py
│   │   ├── passive/
│   │   │   ├── crtsh.py  certspotter.py  censys.py  otx.py  virustotal.py
│   │   │   ├── securitytrails.py  shodan.py  fofa.py  zoomeye.py  netlas.py ...
│   │   │   ├── wayback.py  commoncrawl.py  urlscan.py  hackertarget.py  rapiddns.py ...
│   │   │   ├── github.py  gitlab.py  grepapp.py
│   │   │   ├── searchengines.py
│   │   │   └── bin_subfinder.py  bin_amass.py  bin_assetfinder.py  bin_findomain.py
│   │   │       bin_gau.py  bin_cero.py  bin_shosubgo.py  bin_haktrails.py  bin_bbot.py ...
│   │   ├── active/
│   │   │   ├── bruteforce.py     # puredns/shuffledns or native
│   │   │   ├── permutation.py    # alterx/gotator/dnsgen or native engine
│   │   │   ├── axfr.py  nsec.py  reverse_dns.py  records.py
│   │   │   ├── asn_certscan.py   # asnmap → tlsx/cero
│   │   │   ├── webscrape.py      # CSP/JS/robots/sitemap/html
│   │   │   └── vhost.py
│   │   └── enrich/
│   │       ├── httpx_probe.py  tlsx_sans.py  takeover.py  ipinfo.py
│   ├── report/
│   │   ├── txt.py  json.py  csv.py  stdout.py  summary.py   # summary = final terminal table
│   └── utils/
│       ├── subprocess.py         # stream lines, timeout, kill tree (Windows-safe)
│       └── text.py               # hostname regex extraction from arbitrary text/JSON
└── tests/
    ├── unit/   (normalize, wildcard, permutation, parsers with fixtures)
    ├── plugins/ (respx-mocked API responses per plugin)
    └── integration/ (run against a controlled test domain, marked slow)
```

---

## 6. Key components in detail

### 6.1 Normalization & scope (`core/normalize.py`)
- lowercase; strip `*.`, leading `.`, trailing `.`, `http(s)://`, ports, paths; decode `\n`-joined crt.sh names; IDNA-encode.
- validate with RFC-1123 label regex; drop names > 253 chars; drop email-like.
- **in-scope test**: `host == root or host.endswith("." + root)`; multi-root support (list file) and `--include-out-of-scope` to keep related domains found by CT (reported separately as `related_domains.txt`).
- extraction helper: regex `(?:[a-z0-9-]+\.)+root` applied to *any* text (HTML, JS, JSON) so every plugin can reuse it.

### 6.2 Runner (`core/runner.py`)
- `asyncio.TaskGroup`; global semaphore `--concurrency` (default 20); per-plugin `timeout`; per-host rate limiter for APIs.
- Each plugin streams findings → `store.add(finding)` immediately (so partial results survive Ctrl+C) and updates the rich table.
- Errors are captured into `source_stats.error` and shown at the end, never abort the run.
- Cancel: SIGINT → cancel group → kill child processes (`psutil` tree kill on Windows).

### 6.3 Wildcard detection (`core/dns/wildcard.py`)
- For root and every intermediate parent found (`a.b.example.com` → check `*.b.example.com`), resolve 3–5 random 12-char labels; collect the set of wildcard A/AAAA/CNAME answers.
- A candidate is *wildcard-only* if all its answers ⊆ wildcard answer set for that parent. Keep it flagged (`wildcard=1`) but exclude from "resolved" counts unless `--keep-wildcards`.
- puredns already does this for brute force; the native implementation is required for the aiodns fallback and for passive results.

### 6.4 Mass resolution (`core/dns/massresolve.py`)
- Prefer `puredns resolve --resolvers R --resolvers-trusted T --wildcard-tests 50 --write-wildcards`; else `massdns -r R -t A -o J`; else native `aiodns` pool (round-robin resolvers, retries 2, jitter, `--qps`).
- Output: hostname → {A, AAAA, CNAME}. Store it.

### 6.5 Permutation engine (`plugins/active/permutation.py`)
- External: `alterx -enrich` (uses patterns learned from input) → `gotator -depth 1 -numbers 5 -mindup -adv` → `dnsgen`.
- Native: tokenise known names into words (`dev`, `api`, `01`, `us-east`), build patterns `{word}-{sub}`, `{sub}-{word}`, `{word}.{sub}`, number increments, env/region dictionaries; cap at `--max-permutations` (default 200k) then resolve.
- Only runs on resolved names (quality > quantity); results flagged `source=permutation`.

### 6.6 Recursion (`core/pipeline.py`)
- After stage 2, select resolved names with ≥ 1 extra label beyond root that have `>= --recursion-min-children` (default 3) siblings or are themselves parents (e.g. `api.example.com` when `v1.api.example.com` exists) → treat as sub-roots.
- Run a reduced passive set (cheap/fast sources: crt.sh, certspotter, OTX, subfinder) + permutation + small brute on each sub-root; depth ≤ `--depth`.
- Stop conditions: depth, time budget `--max-time`, zero new findings in a round.

### 6.7 Key ring (`core/config.py`)
```yaml
keys:
  securitytrails: ["k1", "k2"]      # rotated on 429/403
  virustotal: ["k"]
  shodan: ["k"]
  censys: ["id:secret"]
  github: ["ghp_...", "ghp_..."]
  chaos: ["k"]
  fofa: ["email:key"]
  ...
subfinder_provider_config: auto     # generate provider-config.yaml from keys above
```
Env override `ALLFINDER_KEYS__SECURITYTRAILS=k1,k2`. Keys never logged.

### 6.8 External tool wrappers (`utils/subprocess.py`)
- `run_stream(cmd, timeout, parse=line→Finding)`; captures stderr to log file in run dir; exit code ≠ 0 → stats error, partial stdout kept.
- `binaries.py`: `which()` with `$GOPATH/bin`, `~/go/bin`, `~/.allfinder/bin`; records version; `doctor` prints install command per missing tool (from `scripts/install_tools.*`).

### 6.9 Terminal output & reporting

**While running** (normal mode, TTY):
```
allfinder v1.0  target: example.com  mode: passive+resolve
[*] crtsh          done    412 found   88 new   3.1s
[*] subfinder      running  ...
[*] otx            done     96 found    4 new   1.8s
[!] virustotal     skipped  no API key
[!] amass          error    binary not found (run: allfinder doctor)
```
Lines update in place via `rich.live`; with `--no-color` or when piped they print as plain append-only lines so logs stay readable.

**At the end:** a summary table printed to the terminal:
```
Source         Found  Unique  Time
crtsh            412      88  3.1s
subfinder       1203     640  41s
...
Total unique: 1 532   Resolved: 1 210   Wildcard-only: 95   Alive: 802
Output: out/example.com/2026-10-24_16-30/
```

**Files** in `out/<domain>/<timestamp>/` (all plain text, `grep`/`jq` friendly):
`subdomains.txt`, `resolved.txt`, `alive.txt`, `wildcards.txt`, `related_domains.txt`, `results.json` (full records), `results.jsonl` (one record per line), `results.csv`, `sources.txt` (per-source contribution), `run.log`.

**Pipe modes:**
- `--silent` → only hostnames to stdout, nothing else (like SubDomz `-s`): `allfinder enum -d x.com --silent | httpx`.
- `--json-lines` → one JSON record per line to stdout for `jq`.
- Exit codes: `0` ok, `1` usage error, `2` run finished with some source errors, `130` interrupted.

**Compare runs:** `allfinder diff -d example.com` prints hostnames new since the previous run; `--since <run-id>` picks an older baseline. Scheduling/monitoring is left to `cron`/Task Scheduler + `diff`; no built-in notifications.

---

## 7. CLI design

```
allfinder enum -d example.com                    # passive + resolve + report
allfinder enum -l roots.txt --active --probe     # full pipeline
allfinder enum -d example.com --use crtsh,subfinder,otx
allfinder enum -d example.com --exclude amass,searchengines
allfinder enum -d example.com --active --brute large --depth 2 --max-time 2h
allfinder enum -d example.com --passive-only --silent | httpx
allfinder enum -d example.com --resume <run-id>
allfinder sources [--kind passive|active|enrich] [--available]
allfinder doctor                                  # binaries, keys, wordlists, resolvers
allfinder update                                  # resolvers, wordlists, takeover fingerprints
allfinder diff -d example.com [--since <run>]
allfinder config init|show|set keys.shodan=...
```

Flags: `-d/--domain`, `-l/--list`, `-o/--out-dir`, `--use`, `--exclude`, `--active`, `--probe`, `--brute {none,small,medium,large,custom:path}`, `--permute/--no-permute`, `--depth N`, `--concurrency N`, `--qps N`, `--resolvers path`, `--trusted-resolvers path`, `--timeout-per-source S`, `--max-time`, `--keep-wildcards`, `--silent`, `--json-lines`, `--proxy`, `--no-color`, `--keep-tmp`, `-v/-vv`.

---

## 8. Installation story (terminal only)

Everything is installed and run from the shell; no containers, no services.

1. `pipx install allfinder` (or `uv tool install .` from the repo) → `allfinder` command on PATH.
2. `allfinder doctor` → prints a table: binary / found / version / install command. Also checks API keys, resolvers and wordlists.
3. `allfinder update` → downloads resolvers (trickest), wordlists (assetnote tiers), takeover fingerprints into `~/.allfinder/data`.
4. External tools (optional, each adds sources):
   - `scripts/install_tools.sh` (Linux/macOS/WSL): `go install` for subfinder, amass, assetfinder, chaos, haktrails, gau, github-subdomains, gitlab-subdomains, cero, shosubgo, httpx, dnsx, tlsx, alterx, asnmap, katana, nuclei, puredns, shuffledns, gotator; massdns from source; findomain binary.
   - `scripts/install_tools.ps1` (Windows PowerShell): installs Go via winget if missing, then the Go tools that build on Windows (projectdiscovery tools, assetfinder, gau, cero, shosubgo, gotator, alterx). massdns/puredns are not available on Windows → the built-in Python resolver is used automatically; `doctor` prints a one-line note that WSL2 gives faster brute force.

The core (all native passive sources, resolution, wildcard filtering, AXFR, record mining, web scraping, reports) works with **zero external binaries**, so `pipx install` alone already gives a useful tool on Windows.

---

## 9. Milestones

### M0 — Skeleton (1–2 days)
- pyproject, typer app, config loader, models, normalize + tests, SQLite store, rich UI table, logging, `doctor` skeleton.
- **Done when:** `allfinder enum -d example.com --use crtsh` works end-to-end with the native crt.sh plugin and writes `subdomains.txt`.

### M1 — Passive core (3–5 days)
- Native plugins: crtsh, certspotter, otx, hackertarget, rapiddns, anubis, subdomain.center, columbus, wayback, commoncrawl, urlscan, threatminer, riddler, robtex, sitedossier, digitorus, dnsrepo, shrewdeye.
- Binary wrappers: subfinder, amass, assetfinder, findomain, gau+unfurl, cero, haktrails, shosubgo, github-subdomains, gitlab-subdomains, chaos.
- Runner with concurrency/timeouts/error capture; per-source stats; `--use/--exclude`; `sources` command.
- **Done when:** parity with SubDomz on all 19 sources, no tmp files, works on Windows for native + Go tools.

### M2 — Keyed passive sources (3–4 days)
- Key ring + rotation; virustotal, securitytrails, shodan, censys, fofa, zoomeye, netlas, hunter, quake, binaryedge, fullhunt, leakix, chaos (native), passivetotal, whoisxml, c99, dnsdb, bevigil, redhunt, criminalip, dnsdumpster, threatbook, github native, grep.app.
- Auto-generate subfinder `provider-config.yaml` from our keys.
- Search engines behind flag.
- **Done when:** `doctor` shows key status; each keyed plugin has a respx-mocked test.

### M3 — Resolution & wildcard (2–3 days)
- Resolver pool + auto download/validate; wildcard detection (multi-level); puredns/massdns wrapper; aiodns fallback; `resolved.txt`, `wildcards.txt`.
- **Done when:** a wildcard domain (e.g. a test zone with `*.`) yields no false positives.

### M4 — Active discovery (5–7 days)
- Brute force tiers + wordlist manager; permutation (alterx/gotator/dnsgen + native engine); AXFR; NSEC walk; MX/TXT/SPF/SRV mining; reverse DNS over resolved /24s; CNAME chain; ASN → tlsx/cero cert scan; web scrape (CSP/JS/robots/sitemap/HTML); VHost (optional).
- `--active` gate with authorization notice; `--qps` limiter; `--max-time` budget.
- **Done when:** each technique has a unit test on fixtures and an integration test on a controlled domain.

### M5 — Feedback loops & recursion (2–3 days)
- Pipeline rounds: new resolved → permutation → resolve; sub-root recursion with depth; tlsx SANs and web-scrape results fed back; stop conditions.
- `--resume`.
- **Done when:** a run on a mid-size target shows round-2 findings that round-1 lacked, and reruns resume.

### M6 — Enrichment & terminal reports (3–4 days)
- httpx probe (JSON) + native fallback; takeover fingerprints + nuclei; IP/ASN/CDN tagging; final summary table; `results.json`/`.jsonl`/`.csv`; `diff` command; optional naabu.
- **Done when:** `results.json` contains status/title/tech/cname/takeover for every live host and the terminal summary matches the files.

### M7 — Packaging & polish (2–3 days)
- Install scripts (sh + ps1), `update` command, `sources` command printing plugin metadata, CI (ruff, mypy, pytest on Linux + Windows), release to PyPI.
- Optional: bbot / OneForAll / Subdominator wrappers as extras; plugin entry-point docs for third parties.

Total ≈ 4–5 weeks of focused work for v1.0.

---

## 10. Testing strategy

- **Unit:** normalize (100+ edge cases: `*.`, `\n`, IDNA, ports, uppercase), wildcard logic, permutation generator, in-scope filter, parsers for every binary's output format (amass v3/v4/v5, subfinder json, httpx json, massdns json, puredns output).
- **Plugin tests:** every HTTP plugin tested with `respx` fixtures of real API responses (recorded once, committed), including pagination, 429 handling, key rotation, empty/malformed JSON.
- **Binary tests:** wrappers tested with a fake executable on PATH that prints fixture output; timeout and non-zero exit paths.
- **Integration (marked `slow`, opt-in):** run against a domain you control with known subdomains + a wildcard record; assert recall ≥ expected and zero wildcard false positives.
- **Windows CI job** for native path (no massdns) to guarantee fallback works.
- **Terminal output tests:** run the CLI with `--silent` and with stdout piped (non-TTY) and assert stdout contains only hostnames / JSON lines, nothing decorative.

---

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Free APIs change/die (ThreatCrowd, bufferover, crobat already dead) | Plugins isolated; `doctor --check-sources` pings each; CI nightly smoke test |
| Rate limits / bans (crt.sh, search engines) | Per-host limiter, backoff, caching of responses per run, Postgres path for crt.sh |
| Huge brute force on Windows without massdns | Native resolver capped at safe QPS; `doctor` suggests WSL2 for large wordlists |
| amass version output drift | Parse JSON output only; version-detect in `binaries.py` |
| Memory with millions of candidates | Stream to SQLite; sets of hashes; chunked resolution (50k per batch) |
| Legal/ethical misuse of active mode | Explicit `--active` + first-run acknowledgement; docs state authorization requirement |
| Key leakage | Keys only in config/env; redacted in logs and reports |

---

## 12. Immediate next steps

1. Create repo `allfinder/` next to `SubDomz/`, init `pyproject.toml`, venv, `ruff`/`mypy`/`pytest` config.
2. Implement `core/normalize.py` + tests (foundation for every plugin).
3. Implement `plugins/base.py`, `core/registry.py`, `core/runner.py`, `core/store.py`.
4. Implement `crtsh` and `subfinder` plugins → first end-to-end run.
5. Proceed through milestones M1 → M7.
