"""Data files: resolvers, wordlist tiers and takeover fingerprints in ``~/.allfinder/data``.

``allfinder update`` downloads/refreshes them; ``doctor`` reports their state.
A small built-in wordlist ships with the package so ``--brute small`` works
offline.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import httpx
from rich.console import Console

from allfinder.core.config import Config

PACKAGE_DATA = Path(__file__).resolve().parent.parent / "data"

DEFAULT_RESOLVERS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "64.6.64.6",
    "64.6.65.6",
    "76.76.2.0",
    "76.76.10.0",
    "94.140.14.14",
    "94.140.15.15",
    "185.228.168.9",
    "185.228.169.9",
]
DEFAULT_TRUSTED = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]


@dataclass(frozen=True, slots=True)
class DataFile:
    name: str
    filename: str
    url: str
    description: str
    max_age_days: int = 7


DATA_FILES: dict[str, DataFile] = {
    "resolvers": DataFile(
        "resolvers",
        "resolvers.txt",
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
        "public resolvers (trickest)",
        max_age_days=3,
    ),
    "resolvers-trusted": DataFile(
        "resolvers-trusted",
        "resolvers-trusted.txt",
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
        "trusted resolvers (trickest)",
        max_age_days=14,
    ),
    "wordlist-medium": DataFile(
        "wordlist-medium",
        "wordlist-medium.txt",
        "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt",
        "assetnote 2m-subdomains (~2M)",
        max_age_days=90,
    ),
    "wordlist-large": DataFile(
        "wordlist-large",
        "wordlist-large.txt",
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
        "assetnote best-dns-wordlist (~9M)",
        max_age_days=90,
    ),
    "wordlist-small": DataFile(
        "wordlist-small",
        "wordlist-small.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
        "SecLists top 20k subdomains",
        max_age_days=90,
    ),
    "takeover-fingerprints": DataFile(
        "takeover-fingerprints",
        "takeover_fingerprints.json",
        "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json",
        "subdomain takeover fingerprints (can-i-take-over-xyz)",
        max_age_days=14,
    ),
}

BRUTE_TIERS = {"small": "wordlist-small", "medium": "wordlist-medium", "large": "wordlist-large"}


def data_dir(cfg: Config) -> Path:
    return cfg.data_dir / "data"


def path_for(cfg: Config, name: str) -> Path:
    return data_dir(cfg) / DATA_FILES[name].filename


def is_fresh(path: Path, max_age_days: int) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    return (time.time() - path.stat().st_mtime) < max_age_days * 86400


def builtin_path(name: str) -> Path | None:
    """Packaged fallback (small wordlist, fingerprints) if present."""
    candidates = {
        "wordlist-small": PACKAGE_DATA / "subdomains-small.txt",
        "takeover-fingerprints": PACKAGE_DATA / "takeover_fingerprints.json",
    }
    p = candidates.get(name)
    return p if p is not None and p.is_file() else None


def locate(cfg: Config, name: str) -> Path | None:
    """Downloaded file if present, else the packaged fallback, else ``None``."""
    p = path_for(cfg, name)
    if p.is_file() and p.stat().st_size > 0:
        return p
    return builtin_path(name)


def load_resolvers(cfg: Config, override: str | None = None, *, trusted: bool = False) -> list[str]:
    """Resolver IPs from ``override`` file > downloaded list > built-in defaults."""
    sources: list[Path] = []
    if override:
        sources.append(Path(override))
    sources.append(path_for(cfg, "resolvers-trusted" if trusted else "resolvers"))
    for p in sources:
        if p.is_file():
            ips = read_lines(p)
            if ips:
                return ips
    return list(DEFAULT_TRUSTED if trusted else DEFAULT_RESOLVERS)


def read_lines(path: Path) -> list[str]:
    out: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def iter_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def count_lines(path: Path) -> int:
    n = 0
    with path.open("rb") as fh:
        for _ in fh:
            n += 1
    return n


async def download(df: DataFile, dest: Path, *, console: Console | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(60, connect=15), follow_redirects=True
    ) as client:
        async with client.stream("GET", df.url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            with tmp.open("wb") as fh:
                async for chunk in resp.aiter_bytes(1 << 16):
                    fh.write(chunk)
                    done += len(chunk)
            if console is not None:
                size = f"{done / 1_048_576:.1f} MB" if done > 1_048_576 else f"{done // 1024} KB"
                console.print(f"  {df.name}: {size}{'' if not total else ''}")
    tmp.replace(dest)
    return dest


async def update_all(
    cfg: Config,
    *,
    names: Iterable[str] | None = None,
    force: bool = False,
    console: Console | None = None,
    include_large: bool = False,
) -> dict[str, Path | None]:
    """Download missing/stale files.  Large wordlists only with ``include_large``."""
    console = console or Console(stderr=True)
    wanted = (
        list(names) if names else [n for n in DATA_FILES if include_large or n != "wordlist-large"]
    )
    results: dict[str, Path | None] = {}
    for name in wanted:
        df = DATA_FILES[name]
        dest = path_for(cfg, name)
        if not force and is_fresh(dest, df.max_age_days):
            console.print(f"  {name}: up to date ({dest})")
            results[name] = dest
            continue
        console.print(f"  {name}: downloading {df.url}")
        try:
            results[name] = await download(df, dest, console=console)
        except (httpx.HTTPError, OSError) as exc:
            console.print(f"  [yellow]{name}: failed: {exc}[/yellow]")
            results[name] = dest if dest.is_file() else None
    return results


def doctor_files(cfg: Config) -> list[tuple[str, bool, Path]]:
    rows: list[tuple[str, bool, Path]] = []
    for name in DATA_FILES:
        p = locate(cfg, name)
        rows.append((name, p is not None, p or path_for(cfg, name)))
    return rows


def wordlist_for_tier(cfg: Config, tier: str) -> Path | None:
    """``small|medium|large|custom:<path>`` -> file path (or ``None`` if unavailable)."""
    tier = tier.strip()
    if tier in ("", "none"):
        return None
    if tier.startswith("custom:"):
        p = Path(tier.split(":", 1)[1]).expanduser()
        return p if p.is_file() else None
    name = BRUTE_TIERS.get(tier)
    if name is None:
        p = Path(tier).expanduser()
        return p if p.is_file() else None
    return locate(cfg, name)
