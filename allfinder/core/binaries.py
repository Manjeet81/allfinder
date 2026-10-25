"""Locate external tools, read their versions and print install hints."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")

# Tools we know how to use.  Value: (install hint, builds on Windows?)
GO = "go install -v {pkg}@latest"
INSTALL_HINTS: dict[str, tuple[str, bool]] = {
    "subfinder": (GO.format(pkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"), True),
    "amass": (GO.format(pkg="github.com/owasp-amass/amass/v4/..."), True),
    "assetfinder": (GO.format(pkg="github.com/tomnomnom/assetfinder"), True),
    "findomain": ("https://github.com/Findomain/Findomain/releases (download binary)", True),
    "chaos": (GO.format(pkg="github.com/projectdiscovery/chaos-client/cmd/chaos"), True),
    "haktrails": (GO.format(pkg="github.com/hakluke/haktrails"), True),
    "gau": (GO.format(pkg="github.com/lc/gau/v2/cmd/gau"), True),
    "unfurl": (GO.format(pkg="github.com/tomnomnom/unfurl"), True),
    "waybackurls": (GO.format(pkg="github.com/tomnomnom/waybackurls"), True),
    "github-subdomains": (GO.format(pkg="github.com/gwen001/github-subdomains"), True),
    "gitlab-subdomains": (GO.format(pkg="github.com/gwen001/gitlab-subdomains"), True),
    "cero": (GO.format(pkg="github.com/glebarez/cero"), True),
    "shosubgo": (GO.format(pkg="github.com/incogbyte/shosubgo"), True),
    "httpx": (GO.format(pkg="github.com/projectdiscovery/httpx/cmd/httpx"), True),
    "dnsx": (GO.format(pkg="github.com/projectdiscovery/dnsx/cmd/dnsx"), True),
    "tlsx": (GO.format(pkg="github.com/projectdiscovery/tlsx/cmd/tlsx"), True),
    "alterx": (GO.format(pkg="github.com/projectdiscovery/alterx/cmd/alterx"), True),
    "asnmap": (GO.format(pkg="github.com/projectdiscovery/asnmap/cmd/asnmap"), True),
    "katana": (GO.format(pkg="github.com/projectdiscovery/katana/cmd/katana"), True),
    "nuclei": (GO.format(pkg="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"), True),
    "naabu": (GO.format(pkg="github.com/projectdiscovery/naabu/v2/cmd/naabu"), False),
    "shuffledns": (GO.format(pkg="github.com/projectdiscovery/shuffledns/cmd/shuffledns"), False),
    "puredns": (GO.format(pkg="github.com/d3mondev/puredns/v2"), False),
    "massdns": ("git clone https://github.com/blechschmidt/massdns && cd massdns && make", False),
    "gotator": (GO.format(pkg="github.com/Josue87/gotator"), True),
    "dnsgen": ("pipx install dnsgen", True),
    "ffuf": (GO.format(pkg="github.com/ffuf/ffuf/v2"), True),
    "hakrevdns": (GO.format(pkg="github.com/hakluke/hakrevdns"), True),
    "bbot": ("pipx install bbot", False),
    "theHarvester": ("pipx install theHarvester", True),
    "ldns-walk": ("apt install ldnsutils", False),
}

_VERSION_FLAGS: dict[str, list[str]] = {
    "amass": ["-version"],
    "assetfinder": ["--help"],
    "findomain": ["--version"],
    "gau": ["--version"],
    "unfurl": ["--help"],
    "waybackurls": ["-h"],
    "cero": ["-h"],
    "shosubgo": ["-h"],
    "haktrails": ["-h"],
    "github-subdomains": ["-h"],
    "gitlab-subdomains": ["-h"],
    "massdns": ["--help"],
    "puredns": ["--version"],
    "gotator": ["-h"],
    "dnsgen": ["--version"],
    "ffuf": ["-V"],
    "hakrevdns": ["-h"],
    "bbot": ["--version"],
    "theHarvester": ["--help"],
    "ldns-walk": ["-v"],
}


def extra_bin_dirs() -> list[Path]:
    """Directories searched in addition to ``PATH``."""
    dirs: list[Path] = []
    gopath = os.environ.get("GOPATH")
    if gopath:
        dirs.extend(Path(p) / "bin" for p in gopath.split(os.pathsep) if p)
    home = Path.home()
    dirs.append(home / "go" / "bin")
    dirs.append(home / ".allfinder" / "bin")
    dirs.append(home / ".local" / "bin")
    if (gobin := os.environ.get("GOBIN")) and gobin:
        dirs.append(Path(gobin))
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


@lru_cache(maxsize=256)
def which(name: str) -> str | None:
    """Find *name* on PATH or the usual Go/pipx directories; ``None`` if absent."""
    found = shutil.which(name)
    if found:
        return found
    candidates = [name]
    if IS_WINDOWS and not name.lower().endswith(".exe"):
        candidates.append(name + ".exe")
    for d in extra_bin_dirs():
        for c in candidates:
            p = d / c
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
    return None


def clear_cache() -> None:
    which.cache_clear()


def is_available(name: str) -> bool:
    return which(name) is not None


def install_hint(name: str) -> str:
    hint, _ = INSTALL_HINTS.get(name, ("(no install hint known)", True))
    return hint


def supported_on_this_os(name: str) -> bool:
    _, on_windows = INSTALL_HINTS.get(name, ("", True))
    return on_windows or not IS_WINDOWS


@dataclass(slots=True)
class BinaryInfo:
    name: str
    path: str | None
    version: str | None
    hint: str
    supported: bool

    @property
    def found(self) -> bool:
        return self.path is not None


async def version_of(name: str, timeout: float = 8.0) -> str | None:
    """Best-effort version string (first non-empty line of ``tool -version``)."""
    path = which(name)
    if not path:
        return None
    flags = _VERSION_FLAGS.get(name, ["-version"])
    try:
        proc = await asyncio.create_subprocess_exec(
            path,
            *flags,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            proc.kill()
            return "?"
    except (OSError, ValueError):
        return None
    text = out.decode("utf-8", "replace")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if "version" in low or low.startswith("v") and any(ch.isdigit() for ch in low):
            return line[:60]
        return line[:60]
    return "?"


async def inspect(names: list[str] | None = None) -> list[BinaryInfo]:
    names = names or sorted(INSTALL_HINTS)
    infos: list[BinaryInfo] = []
    versions = await asyncio.gather(*(version_of(n) for n in names))
    for name, ver in zip(names, versions, strict=True):
        infos.append(
            BinaryInfo(
                name=name,
                path=which(name),
                version=ver,
                hint=install_hint(name),
                supported=supported_on_this_os(name),
            )
        )
    return infos
