"""Core data models shared by every stage of the pipeline.

Everything here is a plain dataclass (no ORM) so plugins, the store and the
reporters can exchange values without importing each other.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, TypedDict


def utcnow() -> datetime:
    return datetime.now(UTC)


class SourceKind(enum.StrEnum):
    """What a plugin does to the target."""

    PASSIVE = "passive"  # third-party data only, no packets to the target
    ACTIVE = "active"  # touches the target's DNS / HTTP
    ENRICH = "enrich"  # adds data to already-known subdomains


class Requirement(TypedDict, total=False):
    """What a plugin needs before it can run."""

    binaries: list[str]  # e.g. ["subfinder"]
    api_keys: list[str]  # key-ring provider names, e.g. ["securitytrails"]
    files: list[str]  # e.g. ["resolvers", "wordlist"]


@dataclass(slots=True, frozen=True)
class Target:
    """A root domain being enumerated.

    ``roots`` is the full in-scope set (multi-root runs); ``root`` is the one
    this particular task works on.  ``depth`` > 0 means the target is a
    sub-root produced by recursion (e.g. ``api.example.com``).
    """

    root: str
    roots: tuple[str, ...] = ()
    depth: int = 0
    parent: str | None = None

    def __post_init__(self) -> None:
        if not self.roots:
            object.__setattr__(self, "roots", (self.root,))

    @property
    def apex(self) -> str:
        """The user-supplied root this target belongs to (walks up parents)."""
        for r in self.roots:
            if self.root == r or self.root.endswith("." + r):
                return r
        return self.root


@dataclass(slots=True)
class Finding:
    """One hostname reported by one source.  Hostnames must be normalized."""

    hostname: str
    source: str
    ips: list[str] = field(default_factory=list)
    cname: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    ts: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class Resolution:
    """DNS answers for a hostname after mass resolution."""

    hostname: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    wildcard: bool = False
    error: str | None = None

    @property
    def ips(self) -> list[str]:
        return [*self.a, *self.aaaa]

    @property
    def resolved(self) -> bool:
        return bool(self.a or self.aaaa or self.cname)


@dataclass(slots=True)
class HttpInfo:
    """Result of probing one hostname over HTTP(S)."""

    url: str
    status: int | None = None
    title: str | None = None
    tech: list[str] = field(default_factory=list)
    content_length: int | None = None
    final_url: str | None = None
    server: str | None = None
    ip: str | None = None
    cdn: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Subdomain:
    """Aggregated record for one hostname across all sources and stages."""

    hostname: str
    root: str
    sources: set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    resolved: bool = False
    wildcard: bool = False
    ips: list[str] = field(default_factory=list)
    cname: str | None = None
    asn: str | None = None
    org: str | None = None
    http: HttpInfo | None = None
    takeover: dict[str, Any] | None = None
    depth: int = 0
    in_scope: bool = True

    @property
    def alive(self) -> bool:
        return self.http is not None and self.http.status is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "root": self.root,
            "sources": sorted(self.sources),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "resolved": self.resolved,
            "wildcard": self.wildcard,
            "ips": list(self.ips),
            "cname": self.cname,
            "asn": self.asn,
            "org": self.org,
            "http": self.http.to_dict() if self.http else None,
            "takeover": self.takeover,
            "depth": self.depth,
            "in_scope": self.in_scope,
        }


class SourceStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass(slots=True)
class SourceStats:
    """Per-source bookkeeping for the live table and ``sources.txt``."""

    source: str
    status: SourceStatus = SourceStatus.PENDING
    found: int = 0  # findings emitted (with duplicates)
    unique: int = 0  # findings that were new to the store
    duration: float = 0.0
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "found": self.found,
            "unique": self.unique,
            "duration": round(self.duration, 3),
            "error": self.error,
        }


@dataclass(slots=True)
class RunInfo:
    """Metadata about one invocation of ``allfinder enum``."""

    id: str
    roots: tuple[str, ...]
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    args: dict[str, Any] = field(default_factory=dict)
    version: str = ""
    out_dir: str | None = None
