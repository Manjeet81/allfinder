# How allfinder works

This document explains the engine in depth: the pipeline, every discovery
technique, how the stages feed each other, and the data model that ties it
together. It is written for security engineers who want to understand exactly
what the tool does to a target and why.

---

## 1. The core idea

Most subdomain tools run a pile of sources side by side and `sort -u` the
output. allfinder does that too, but the important part is that **every stage
feeds the next and loops back**:

```
         passive sources ─┐
                          ▼
   ┌───────────────> resolution + wildcard filtering ──┐
   │                      │                             │
   │                      ▼                             │
   │   active discovery (brute / permute / AXFR /       │  new names
   │   records / reverse-DNS / web-scrape) ─────────────┘
   │                      │
   │   recursion: promising sub-roots become new roots ─┘
   │                      │
   │                      ▼
   │              enrichment (HTTP probe / takeover / ASN)
   │                      │
   └──────────────────────┴──────> reports (txt / json / csv)
```

A hostname found by crt.sh is resolved; its resolved IP seeds reverse-DNS; its
live HTTP response is scraped for more names; a name like `api.example.com`
with children becomes a sub-root that the passive sources run against again.
Quantity from passive, precision from active, and a feedback loop that keeps
turning one finding into the next.

Everything runs on `asyncio`: sources execute concurrently with per-source
timeouts and a global concurrency limit, and each finding is written to the
store the moment it arrives, so a `Ctrl+C` or a timeout never loses partial
results.

---

## 2. Pipeline stages

| # | Stage | Runs | Gate |
|---|-------|------|------|
| 1 | **passive** | ~60 third-party sources concurrently | always |
| 2 | **resolve** | wildcard detection → mass resolution → filter | always (skip with `--passive-only`) |
| 3 | **active** | brute force, permutation, AXFR/NSEC, record mining, reverse DNS, web scrape | `--active` |
| 4 | **recurse** | re-run cheap passive + permutation on new sub-roots | `--depth N` |
| 5 | **enrich** | HTTP probe, subdomain-takeover check, ASN/org tagging | `--probe` |
| 6 | **report** | write all output files + terminal summary | always |

Stages 2→3 and 2→4 loop back into resolution, bounded by `--depth` and the
`--max-time` budget. Passive + resolve + report always run; active and
enrichment are explicitly opt-in because they send traffic to the target.

---

## 3. Stage 1 — passive sources

Each source is a **plugin**: one Python file implementing a tiny async
interface that yields `Finding` objects. There are two kinds:

- **Native (≈45):** plain HTTP/DNS calls implemented in Python with a shared
  `httpx` client — crt.sh, Cert Spotter, OTX, VirusTotal, SecurityTrails,
  Shodan, Censys, FOFA, ZoomEye, Netlas, Hunter, Quake, BinaryEdge, FullHunt,
  LeakIX, Chaos, PassiveTotal, WhoisXML, C99, DNSDB, BeVigil, RedHunt,
  CriminalIP, DNSDumpster, ThreatBook, HackerTarget, RapidDNS, Anubis,
  subdomain.center, Columbus, ThreatMiner, Riddler, Robtex, SiteDossier,
  Digitorus, DNSRepo, ShrewdEye, Wayback, CommonCrawl, urlscan, GitHub code
  search, grep.app, and the search engines.
- **Binary wrappers:** heavy tools that are not worth re-implementing are run
  as external processes and their stdout is parsed — subfinder, amass,
  assetfinder, findomain, gau, waybackurls, cero, chaos, shosubgo, haktrails,
  github-subdomains, gitlab-subdomains.

Why both: re-implementing crt.sh is a one-line HTTP call, but re-implementing
amass is wasteful. Native sources work with **zero external binaries**, so a
bare `pip install` already gives a useful tool; binaries are optional and each
one simply adds more sources.

**Provenance** is recorded for every name: which sources found it, and when.
That lets the final `sources.txt` show which source actually earned its keep
for this target.

**Graceful degradation:** a missing binary or API key marks the source
*skipped* with a one-line reason; a dead API (ThreatCrowd, bufferover and
friends come and go) marks it *error* — neither ever aborts the run. A
third-party service that is unreachable or blocks anonymous clients is reported
as *skipped*, not a failure.

### Keyed sources and the key ring

Sources that need an API key read it from a **key ring** built from
`~/.allfinder/config.yaml` (or `ALLFINDER_KEYS__*` env vars). You can give
several keys per provider; they rotate automatically on `401/403/429`, and a
key that hits its limit is parked on a cooldown while the others keep working.
Keys are never written to the log or reports — they are redacted everywhere.

allfinder also generates a subfinder `provider-config.yaml` from the same key
ring, so the wrapped subfinder shares your credentials without a second copy.

---

## 4. Normalization and scope

Whatever a source returns — a URL, a `*.` wildcard, a crt.sh newline-joined
blob, upper-case, IDNA/unicode, a trailing dot, a port, a JS-escaped
`api\.example\.com`, a percent-encoded `api%2Eexample%2Ecom` — passes through
one normalizer before it is stored. The result is always a clean, lower-case,
IDNA-encoded, RFC-1123-valid hostname. IP addresses, email addresses and
all-numeric TLDs are rejected.

A **scope** object decides what is in scope: a host is in scope if it equals a
root or ends with `.<root>`. Multi-root runs (`-l roots.txt`) are supported;
the most specific root wins. Names discovered out of scope (a partner domain in
an SPF record, a CT certificate that also covers another company) are not
dropped — they are kept separately in `related_domains.txt`.

A single regex extractor finds every in-scope hostname inside arbitrary text —
HTML, minified JavaScript, JSON, logs — and every plugin reuses it, which is
how web-scraping and code-search sources mine names out of noise.

---

## 5. Stage 2 — resolution and wildcard filtering

Candidates are only useful if they resolve, and wildcard DNS makes most of them
lie. This stage separates the real from the noise.

### Multi-level wildcard detection

For the root and **every intermediate parent** of a candidate
(`a.b.example.com` → `*.b.example.com`, `*.example.com`), allfinder resolves a
few random 12-character labels and records the set of answers that come back. A
candidate whose answers are a subset of a parent's wildcard answer set is
flagged `wildcard=True` and excluded from the "resolved" count (unless you pass
`--keep-wildcards`). Doing this per level catches wildcards that only exist deep
in the tree, not just at the apex.

### Mass resolution backends

- **puredns** (preferred when installed) — fastest, does its own wildcard
  handling with a resolver pool.
- **massdns** — used if puredns is absent.
- **native aiodns pool** (always available) — a pure-Python resolver over a
  round-robin pool of public resolvers, rate-limited by `--qps`, with retries,
  automatic bad-resolver eviction, and an IPv4/IPv6 path. This is what runs on
  Windows, where massdns/puredns do not build.

Resolver lists come from `--resolvers` / trickest's list (downloaded by
`allfinder update`) or a built-in default set. Actively discovered names
(brute force, permutation) are **re-validated against trusted resolvers** so a
poisoned public resolver cannot inject a false positive.

---

## 6. Stage 3 — active discovery

Opt-in with `--active`. These techniques touch the target's DNS and HTTP, so
the tool prints an authorization notice and honours `--qps` and `--max-time`.

- **Brute force** — generates `word.root` from a wordlist tier
  (`--brute small|medium|large|custom:<path>`), resolves in chunks, keeps only
  names that answer and are not wildcard-only. A compact wordlist ships with
  the package so `--brute small` works offline; larger assetnote/SecLists tiers
  are fetched by `allfinder update`.
- **Permutation engine** — tokenises the labels of names that already resolve
  (`api-dev` → `api`, `dev`; `web01` → `web`, `01`), then builds variants:
  `word-sub`, `sub-word`, `word.sub`, number increments and zero-padding, and
  region/environment dictionaries. It runs only on resolved names (quality over
  quantity), caps at `--max-permutations`, then resolves. `alterx` is wrapped as
  an alternative generator when present.
- **Zone transfer (AXFR)** — attempts a full zone transfer against every NS of
  the zone. Rarely allowed, but when it is, it dumps the entire zone in one
  request.
- **NSEC walk** — when a DNSSEC zone uses NSEC, allfinder walks the NSEC chain
  to enumerate names (falls back automatically when AXFR is refused).
- **Record mining** — reads SOA, NS, MX, TXT, SRV and CNAME records. SPF
  `include:`/`redirect=` chains reveal mail and third-party infrastructure;
  SRV service records (`_sip._tcp`, `_autodiscover._tcp`, …) reveal internal
  services; CNAME targets of known names reveal third-party and internal hosts.
- **Reverse DNS (PTR)** — over the `/24` of every resolved in-scope IP (private
  ranges skipped), keeping only PTR names that are themselves in scope.
- **Web scraping** — for every live host, mines more in-scope names from CSP /
  `Access-Control-Allow-Origin` / `Link` headers, from the HTML body, from
  linked JavaScript files, and from `robots.txt`, `sitemap.xml`,
  `security.txt` and other `.well-known` resources.

Every active find flows straight back into stage 2 (resolution), so a
permutation hit or a scraped name is validated and can itself seed the next
round.

---

## 7. Stage 4 — recursion and feedback loops

After resolution, allfinder looks for names that are themselves parents — e.g.
`api.example.com` when `v1.api.example.com` and `v2.api.example.com` exist, or
any name with at least `--recursion-min-children` siblings. Each becomes a
**sub-root**. A cheap, fast subset of passive sources plus the permutation
engine runs against each sub-root, and (in active mode) the active techniques
too, feeding results back into resolution. Depth is bounded by `--depth`, and
the whole loop stops early on a round that finds nothing new or when the
`--max-time` budget runs out. This is how deep internal trees
(`a.b.c.api.example.com`) get discovered that a single flat pass would miss.

---

## 8. Stage 5 — enrichment

Opt-in with `--probe`. Adds data to names already discovered; it does not find
new names (except what the probe's own responses reveal).

- **HTTP probe** — status code, page title, detected technologies, web server,
  content length, redirect chain, final URL, IP and CDN. Uses the `httpx`
  binary when present (fast, rich tech detection) and a native fallback probe
  otherwise, so probing works with no external tools.
- **Subdomain takeover** — for every name with a CNAME, matches the CNAME
  against a fingerprint database (can-i-take-over-xyz, downloaded by
  `allfinder update`, plus a built-in set) and fetches the page to confirm the
  service's "unclaimed" marker. Dangling CNAMEs (CNAME present but the name does
  not resolve) are flagged too. Confirmed takeovers are called out in the
  terminal.
- **ASN / org tagging** — resolved IPs are tagged with ASN and organisation via
  a batch IP lookup, so you can see which hosts sit behind a CDN vs the target's
  own ranges.

---

## 9. Data model and provenance

State lives in a single SQLite database (`~/.allfinder/allfinder.db`), which is
what makes runs **resumable** and **diffable**:

- `targets` — the root domains ever scanned.
- `runs` — each invocation, with its arguments and timing.
- `subdomains` — one row per hostname: resolved/wildcard flags, IPs, CNAME,
  ASN/org, HTTP status/title/tech, takeover result, depth, in-scope flag, and
  first/last-seen run.
- `findings` — the many-to-many provenance: which source reported which name in
  which run.
- `source_stats` — per-source counts, timing and errors for each run.

Because every name records the run it was first seen in, `allfinder diff -d
example.com` is a simple query: the hostnames new since the previous run (or
since any `--since <run-id>` baseline). Pair it with `cron` / Task Scheduler for
continuous monitoring without any built-in daemon.

---

## 10. Output

Everything is written to `out/<domain>/<timestamp>/`, all plain and
`grep`/`jq`-friendly:

| file | contents |
|------|----------|
| `subdomains.txt` | every in-scope hostname |
| `resolved.txt` / `wildcards.txt` | names that resolve / wildcard-only names |
| `alive.txt` | URLs that answered the HTTP probe |
| `related_domains.txt` | out-of-scope names found via CT / SPF / records |
| `results.json` / `.jsonl` | full records (one document / one per line) |
| `results.csv` | the same, spreadsheet-friendly |
| `sources.txt` | per-source contribution and timing |
| `run.log` | full run log, API keys redacted |

Pipe modes keep stdout clean for tooling: `--silent` emits only hostnames
(`allfinder enum -d x.com --silent | httpx`), `--json-lines` emits one JSON
record per line for `jq`. Exit codes: `0` ok, `1` usage error, `2` finished
with some source errors, `130` interrupted (partial results still written).

---

## 11. Extending it

A new source or technique is one file implementing the plugin interface
(`allfinder/plugins/base.py`): set a name, a kind (passive / active / enrich),
its requirements (binaries or API keys), and an `async def run()` that yields
findings. Built-in plugins are auto-discovered; third-party packages can
register their own through the `allfinder.plugins` entry-point group, so you can
ship a private source as a separate pip package without touching the core.
