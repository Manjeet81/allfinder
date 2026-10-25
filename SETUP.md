# Setup guide (for beginners)

This walks you through everything *after* installing allfinder: the first
commands, which API keys are worth adding and where to get them, the optional
external tools, and the data files. Follow it top to bottom.

> **You do not need any of this to start.** allfinder ships with ~20 free
> sources that need no key and no extra tools. Keys and tools only add *more*
> sources. If you just want results now, run `allfinder enum -d example.com`
> and come back here later.

**First, how to run it.** The installer puts `allfinder` inside the project's
`.venv`, so typing just `allfinder` gives "command not found". Pick one way to
run it and use it everywhere below:

```bash
# Option 1 — run directly (no setup)
.venv/bin/allfinder doctor            # Windows: .\.venv\Scripts\allfinder doctor

# Option 2 — activate the venv once, then plain `allfinder` works in this terminal
source .venv/bin/activate             # Windows: .\.venv\Scripts\Activate.ps1
allfinder doctor

# Option 3 — install system-wide so `allfinder` works from any folder
pipx install .                        # run inside the allfinder folder
```

Throughout this guide, `allfinder …` means whichever of the above you chose.

---

## Step 1 — the first three commands

```bash
allfinder doctor          # shows what is installed, what keys you have, what is missing
allfinder update          # downloads resolvers, wordlists and takeover fingerprints
allfinder config init     # creates the config file for your API keys
```

`doctor` is your map: it prints three tables — external binaries, API keys, and
data files — with a clear "yes / no" for each. Run it any time to see what is
set up.

`config init` creates the file at:

- **Windows:** `C:\Users\<you>\.allfinder\config.yaml`
- **Linux/macOS:** `~/.allfinder/config.yaml`

---

## Step 2 — API keys

Many sources are free and need nothing. Some need an API key, and a few free
ones accept an optional key to raise their limits. You can add as many or as
few as you like — every missing key simply means that one source is skipped.

### How to add a key

Two easy ways. Pick one.

**A) Command (simplest):**

```bash
allfinder config set keys.virustotal=YOUR_KEY_HERE
allfinder config set keys.shodan=KEY1,KEY2        # several keys rotate automatically
```

**B) Edit the file** `~/.allfinder/config.yaml` under the `keys:` section:

```yaml
keys:
  virustotal: ["YOUR_KEY_HERE"]
  shodan: ["KEY1", "KEY2"]
  censys: ["API_ID:API_SECRET"]     # note the id:secret format
```

**C) Environment variable** (good for CI / not saving to disk):

```bash
# Linux/macOS
export ALLFINDER_KEYS__VIRUSTOTAL=YOUR_KEY
# Windows PowerShell
$env:ALLFINDER_KEYS__VIRUSTOTAL="YOUR_KEY"
```

Your keys are **never** written to logs or reports — they are redacted
everywhere. After adding keys, run `allfinder doctor` to confirm they are seen.

### Which keys, and where to get them

Most have a **free tier** that is plenty for recon. Sign up, find the "API key"
in your account/profile, and paste it in. A few use a special format — that is
noted in the last column.

**Free tier available (recommended first):**

| Provider | config key | Where to get it | Format |
|---|---|---|---|
| VirusTotal | `virustotal` | virustotal.com → sign up → profile → API key | token |
| SecurityTrails | `securitytrails` | securitytrails.com → account → API | token |
| Censys | `censys` | censys.io → account → API credentials | `id:secret` |
| Chaos (ProjectDiscovery) | `chaos` | cloud.projectdiscovery.io → API key | token |
| GitHub (code search) | `github` | github.com → Settings → Developer settings → Personal access token (classic), scope `repo`/`public_repo` | token(s) |
| GitLab | `gitlab` | gitlab.com → Preferences → Access tokens (`read_api`) | token |
| Netlas | `netlas` | netlas.io → account → API key | token |
| FullHunt | `fullhunt` | fullhunt.io → account → API key | token |
| BinaryEdge | `binaryedge` | binaryedge.io → account → API | token |
| LeakIX | `leakix` | leakix.net → settings → API key | token |
| BeVigil | `bevigil` | bevigil.com → OSINT API | token |
| CriminalIP | `criminalip` | criminalip.io → my page → API key | token |
| Hunter | `hunter` | hunter.how → account → API key | token |
| WhoisXML | `whoisxml` | whoisxmlapi.com → account → API key | token |
| urlscan.io | `urlscan` | urlscan.io → settings → API key (optional, raises limits) | token |
| RedHunt Labs | `redhunt` | devportal.redhuntlabs.com → API key | token |

**Mostly paid (add if you have access):**

| Provider | config key | Where to get it | Format |
|---|---|---|---|
| Shodan | `shodan` | shodan.io → account → API key (membership) | token |
| FOFA | `fofa` | fofa.info → account → API | `email:key` |
| ZoomEye | `zoomeye` | zoomeye.org → account → API key | token |
| Quake (360) | `quake` | quake.360.net → account → token | token |
| C99 | `c99` | api.c99.nl → paid key | token |
| DNSDB (Farsight) | `dnsdb` | domaintools.com / farsight → API key | token |
| ThreatBook | `threatbook` | threatbook.io → API key | token |
| DNSDumpster | `dnsdumpster` | dnsdumpster.com → API key | token |
| PassiveTotal / RiskIQ | `passivetotal` | community.riskiq.com (legacy) | `user:key` |

**Free, optional key (works without one, key raises limits):**

| Provider | config key | Note |
|---|---|---|
| Cert Spotter | `certspotter` | works keyless; key = more queries |
| AlienVault OTX | `otx` | works keyless; key = more |
| HackerTarget | `hackertarget` | works keyless (~50/day per IP); key = more |
| DNSRepo | `dnsrepo` | works keyless for small domains |

> Free tiers, sign-up pages and limits change over time. If a key stops
> working, allfinder just marks that source "error" or "skipped" and keeps
> going — it never breaks the run. Run `allfinder sources --available` to see
> exactly which sources are usable right now.

### The absolute-minimum useful set

If you want impact for the least effort, start with these free keys:
**VirusTotal, SecurityTrails, Censys, Chaos, GitHub.** That already covers most
of what the big tools pull.

---

## Step 3 — optional external tools

These are separate programs allfinder can drive. Each one you install adds more
sources. **They are optional** — the native pipeline works without any of them.

Install them with the bundled script:

- **Windows (PowerShell):** `scripts\install_tools.ps1`
- **Linux / macOS / WSL:** `scripts/install_tools.sh`

The script installs Go if needed, then builds the tools. What you get:

- **subfinder** — a passive aggregator (dozens of sources itself).
- **amass** — deep passive/active enumeration.
- **assetfinder, findomain, gau, waybackurls** — more passive sources.
- **cero, chaos, shosubgo, haktrails, github-subdomains, gitlab-subdomains** —
  certificate-SAN and keyed sources.
- **httpx** — faster, richer HTTP probing (used by `--probe`).
- **puredns / massdns** (Linux/macOS/WSL only) — very fast mass DNS resolution
  and brute force.
- **alterx** — extra permutation generation.

On **Windows**, `massdns` and `puredns` do not build — allfinder automatically
uses its built-in Python resolver instead. For very large brute-force wordlists,
run allfinder inside **WSL2** where `massdns` is available and much faster.

After installing, run `allfinder doctor` again — the tools you added will now
show "yes".

---

## Step 4 — resolvers and wordlists

`allfinder update` (from Step 1) downloads:

- **resolvers** — a vetted list of public DNS resolvers used for mass
  resolution (refreshed from the trickest list).
- **wordlists** — tiers for `--brute small|medium|large`. A small list ships
  with allfinder so `--brute small` works offline; `medium` and `large` are
  downloaded.
- **takeover fingerprints** — the database used by the subdomain-takeover check.

To also fetch the big ~9M wordlist (optional, large download):

```bash
allfinder update --force --large      # or: python scripts/update_wordlists.py --large
```

You can always point at your own lists: `--resolvers path/to/resolvers.txt` and
`--brute custom:path/to/wordlist.txt`.

---

## Step 5 — confirm everything

```bash
allfinder doctor                  # all three tables should show what you set up
allfinder sources --available     # the exact sources usable right now
```

If a source shows as unavailable, `doctor` tells you why — a missing binary or
a missing key — and the install command or config key to fix it.

---

## Step 6 — beginner recon recipes

```bash
# 1. Quick & safe: free passive sources + resolution, no keys or tools needed
allfinder enum -d example.com

# 2. Only the fastest free sources, results straight to a file
allfinder enum -d example.com --use crtsh,certspotter,otx,anubis,hackertarget

# 3. After adding keys and tools: a thorough passive sweep
allfinder enum -d example.com

# 4. Full engagement (AUTHORIZED targets only): active + recursion + probing
allfinder enum -d example.com --active --probe --depth 2

# 5. Feed live hosts into your next tool
allfinder enum -d example.com --silent | httpx -json

# 6. What changed since last time?
allfinder diff -d example.com
```

Results land in `out/<domain>/<timestamp>/` — open `subdomains.txt` for the
list, `results.json` for everything (IPs, HTTP, takeover, ASN), and
`sources.txt` to see which source found the most.

> **Reminder:** recipes 1–3 and 5 are passive/safe. Recipe 4 (`--active`,
> `--probe`) sends traffic to the target — only run it against systems you are
> authorized to test.

For how the engine actually works under the hood, see
[HOW_IT_WORKS.md](HOW_IT_WORKS.md).
