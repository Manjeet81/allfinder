"""Hostname normalization, validation, scope checks and text extraction.

This module is the foundation every plugin builds on: whatever a source
returns (URLs, ``*.`` wildcards, crt.sh newline-joined names, upper-case,
IDNA, trailing dots, ports, ...) goes through :func:`normalize_hostname`
before it is stored, so the rest of the pipeline only ever sees clean,
lower-case, dot-separated ASCII hostnames.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from urllib.parse import unquote

try:  # idna gives proper UTS-46 mapping; the stdlib codec is the fallback
    import idna as _idna
except ImportError:  # pragma: no cover - idna ships with httpx
    _idna = None  # type: ignore[assignment]

MAX_HOSTNAME_LEN = 253
MAX_LABEL_LEN = 63

# RFC 1123 label plus '_' (used by real DNS names such as _dmarc, _sip._tcp).
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_PORT_RE = re.compile(r":\d{1,5}$")
_WS_RE = re.compile(r"\s+")

# Separators crt.sh / CT logs / HTML scrapers use to join several names.
_SPLIT_RE = re.compile(r"[\s,;|<>\"'()\[\]{}]+")


def _strip_url_parts(value: str) -> str | None:
    """Return the host part of *value* (which may be a URL or a bare name)."""
    had_scheme = False
    if _SCHEME_RE.match(value):
        value = _SCHEME_RE.sub("", value, count=1)
        had_scheme = True
    elif value.startswith("//"):
        value = value[2:]
        had_scheme = True

    # authority ends at the first path / query / fragment delimiter
    for sep in ("/", "?", "#", "\\"):
        idx = value.find(sep)
        if idx != -1:
            value = value[:idx]

    if "@" in value:
        if had_scheme:
            value = value.rsplit("@", 1)[1]  # userinfo@host
        else:
            return None  # looks like an e-mail address

    if value.startswith("["):  # IPv6 literal
        return None

    value = _PORT_RE.sub("", value)
    return value


def _to_ascii(value: str) -> str | None:
    if value.isascii():
        return value
    try:
        if _idna is not None:
            return _idna.encode(value, uts46=True).decode("ascii")
        return value.encode("idna").decode("ascii")
    except Exception:
        return None


def normalize_hostname(raw: str | None, *, allow_single_label: bool = False) -> str | None:
    """Normalize *raw* into a canonical hostname or return ``None`` if invalid.

    Steps: trim, strip scheme / path / port / userinfo, lower-case, drop
    ``*.`` and leading/trailing dots, IDNA-encode, validate every label.

    >>> normalize_hostname("*.API.Example.com.")
    'api.example.com'
    >>> normalize_hostname("https://user:pw@Dev.example.com:8443/x?y")
    'dev.example.com'
    >>> normalize_hostname("1.2.3.4") is None
    True
    """
    if not raw:
        return None
    value = raw.strip().strip("﻿")
    if not value:
        return None

    # percent-encoded dots sometimes appear in scraped JS / URLs
    if "%2e" in value.lower():
        value = unquote(value)
    # JS-escaped dots: api\.example\.com
    value = value.replace("\\.", ".")

    value = _WS_RE.sub("", value)  # no whitespace is ever legal inside a hostname
    host = _strip_url_parts(value)
    if not host:
        return None

    host = host.lower().strip(".")

    # drop wildcard labels at the front: *.a.b, *.*.a.b, *a.b
    while host.startswith("*"):
        host = host.lstrip("*").lstrip(".")
    if not host or "*" in host:
        return None

    # collapse accidental double dots ("api..example.com" from bad concatenation)
    while ".." in host:
        host = host.replace("..", ".")

    ascii_host = _to_ascii(host)
    if ascii_host is None:
        return None
    host = ascii_host.lower().strip(".")

    if len(host) > MAX_HOSTNAME_LEN:
        return None

    labels = host.split(".")
    if len(labels) < 2 and not allow_single_label:
        return None
    for label in labels:
        if not label or len(label) > MAX_LABEL_LEN or not _LABEL_RE.match(label):
            return None

    # reject IPv4 addresses and all-numeric TLDs
    if labels[-1].isdigit():
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None

    return host


def split_names(value: str) -> list[str]:
    """Split a blob that may contain several names (crt.sh ``name_value``)."""
    if not value:
        return []
    return [part for part in _SPLIT_RE.split(value) if part]


def normalize_many(values: Iterable[str | None]) -> set[str]:
    """Normalize an iterable of raw values, dropping invalid ones."""
    out: set[str] = set()
    for raw in values:
        if raw is None:
            continue
        for part in split_names(raw):
            host = normalize_hostname(part)
            if host:
                out.add(host)
    return out


# --------------------------------------------------------------------------- scope


def in_scope(host: str, root: str) -> bool:
    """``True`` if *host* equals *root* or is below it."""
    return host == root or host.endswith("." + root)


class Scope:
    """A set of in-scope root domains with fast membership tests."""

    __slots__ = ("_roots",)

    def __init__(self, roots: Iterable[str]) -> None:
        normalized: list[str] = []
        for r in roots:
            host = normalize_hostname(r, allow_single_label=True)
            if not host:
                raise ValueError(f"invalid root domain: {r!r}")
            if host not in normalized:
                normalized.append(host)
        if not normalized:
            raise ValueError("scope needs at least one root domain")
        # longest first so root_for() prefers the most specific root
        self._roots: tuple[str, ...] = tuple(sorted(normalized, key=len, reverse=True))

    @property
    def roots(self) -> tuple[str, ...]:
        return self._roots

    def root_for(self, host: str) -> str | None:
        """Return the root that *host* belongs to, or ``None`` if out of scope."""
        for root in self._roots:
            if in_scope(host, root):
                return root
        return None

    def __contains__(self, host: object) -> bool:
        return isinstance(host, str) and self.root_for(host) is not None

    def filter(self, hosts: Iterable[str]) -> set[str]:
        return {h for h in hosts if h in self}

    def __iter__(self) -> Iterator[str]:
        return iter(self._roots)

    def __len__(self) -> int:
        return len(self._roots)

    def __repr__(self) -> str:
        return f"Scope({list(self._roots)!r})"


def labels_below(host: str, root: str) -> list[str]:
    """Labels of *host* that sit below *root*: ``a.b.example.com`` -> ``['a','b']``."""
    if host == root:
        return []
    if not in_scope(host, root):
        raise ValueError(f"{host} is not under {root}")
    return host[: -(len(root) + 1)].split(".")


def parents(host: str, root: str) -> list[str]:
    """Intermediate parents between *host* (exclusive) and *root* (inclusive).

    ``a.b.c.example.com`` -> ``['b.c.example.com', 'c.example.com', 'example.com']``
    """
    out: list[str] = []
    labels = labels_below(host, root)
    for i in range(1, len(labels)):
        out.append(".".join(labels[i:]) + "." + root)
    out.append(root)
    return out


def depth_below(host: str, root: str) -> int:
    """Number of labels *host* has below *root* (``api.example.com`` -> 1)."""
    return len(labels_below(host, root))


# --------------------------------------------------------------------------- extraction

_HOST_CHARS = r"[a-zA-Z0-9_\-]"


def hostname_pattern(roots: Iterable[str]) -> re.Pattern[str]:
    """Compile a regex matching any ``sub.<root>`` or bare ``<root>`` in free text."""
    alts = "|".join(re.escape(r) for r in sorted(set(roots), key=len, reverse=True))
    if not alts:
        raise ValueError("at least one root is required")
    return re.compile(
        rf"(?<![a-zA-Z0-9_\-.])((?:\*\.)?(?:{_HOST_CHARS}+\.)*(?:{alts}))(?!\.?[a-zA-Z0-9\-])",
        re.IGNORECASE,
    )


def extract_hostnames(text: str, roots: Iterable[str]) -> set[str]:
    """Find every in-scope hostname inside arbitrary text (HTML, JS, JSON, logs).

    Handles JS-escaped (``api\\.example\\.com``), ``\\u002e`` and percent-encoded
    dots so names hidden in minified bundles are still found.
    """
    if not text:
        return set()
    roots_list = [normalize_hostname(r, allow_single_label=True) or r for r in roots]
    cleaned = text.replace("\\.", ".").replace("\\u002e", ".").replace("\\u002E", ".")
    if "%2e" in cleaned.lower():
        cleaned = unquote(cleaned)
    pat = hostname_pattern(roots_list)
    scope = Scope(roots_list)
    out: set[str] = set()
    for m in pat.finditer(cleaned):
        host = normalize_hostname(m.group(1))
        if host and host in scope:
            out.add(host)
    return out
