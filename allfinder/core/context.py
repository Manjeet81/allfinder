"""RunContext: everything a plugin or stage needs, bundled in one object."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from allfinder.core import binaries
from allfinder.core.config import Config, KeyRing
from allfinder.core.http import RateLimiter
from allfinder.core.models import Finding, RunInfo, SourceStats
from allfinder.core.normalize import Scope
from allfinder.core.store import Store

if TYPE_CHECKING:
    from allfinder.core.dns.resolver_pool import ResolverPool


@dataclass(slots=True)
class RunOptions:
    """CLI-level switches for one run (already merged with config/profile)."""

    active: bool = False
    probe: bool = False
    passive_only: bool = False
    brute: str = "none"
    permute: bool = True
    depth: int = 1
    concurrency: int = 20
    qps: int = 500
    timeout_per_source: int | None = None  # None = plugin default / config default
    max_time: float | None = None  # seconds
    keep_wildcards: bool = False
    include_out_of_scope: bool = False
    silent: bool = False
    json_lines: bool = False
    no_color: bool = False
    keep_tmp: bool = False
    verbosity: int = 0
    use: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    resolvers: str | None = None
    trusted_resolvers: str | None = None
    search_engines: bool = False
    resume: str | None = None
    max_permutations: int = 200_000
    recursion_min_children: int = 3
    max_new_per_round: int = 50_000
    skip_resolve: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "probe": self.probe,
            "passive_only": self.passive_only,
            "brute": self.brute,
            "permute": self.permute,
            "depth": self.depth,
            "concurrency": self.concurrency,
            "qps": self.qps,
            "timeout_per_source": self.timeout_per_source,
            "max_time": self.max_time,
            "keep_wildcards": self.keep_wildcards,
            "include_out_of_scope": self.include_out_of_scope,
            "use": list(self.use),
            "exclude": list(self.exclude),
            "search_engines": self.search_engines,
            "resume": self.resume,
        }


@dataclass(slots=True)
class RunContext:
    config: Config
    options: RunOptions
    scope: Scope
    keys: KeyRing
    http: httpx.AsyncClient
    store: Store
    run: RunInfo
    out_dir: Path
    tmpdir: Path
    limiter: RateLimiter = field(default_factory=RateLimiter)
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("allfinder"))
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    started: float = field(default_factory=time.monotonic)
    on_stats: Callable[[SourceStats], None] | None = None
    on_log: Callable[[str, str], None] | None = None  # (level, message)
    on_finding: Callable[[Finding, bool], None] | None = None  # (finding, is_new)
    resolver_pool: ResolverPool | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    # -- helpers ---------------------------------------------------------
    @property
    def data_dir(self) -> Path:
        return self.config.data_dir

    def binary(self, name: str) -> str | None:
        return binaries.which(name)

    def timeout_for(self, source: str, default: int) -> float:
        """Effective timeout: per-source override > CLI flag > max(plugin, config default)."""
        override = self.config.timeout_for(source)
        if override is not None:
            base = float(override)
        elif self.options.timeout_per_source is not None:
            base = float(self.options.timeout_per_source)
        else:
            base = float(max(default, self.config.limits.timeout_per_source))
        remaining = self.remaining()
        if remaining is not None:
            base = max(1.0, min(base, remaining))
        return base

    def remaining(self) -> float | None:
        """Seconds left in the ``--max-time`` budget, or ``None`` if unlimited."""
        if self.options.max_time is None:
            return None
        return max(0.0, self.options.max_time - (time.monotonic() - self.started))

    def out_of_time(self) -> bool:
        rem = self.remaining()
        return rem is not None and rem <= 0

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def notice(self, message: str, level: str = "info") -> None:
        """Human-facing line (goes to the UI, not just the log)."""
        getattr(self.log, level if level != "warn" else "warning")(message)
        if self.on_log is not None:
            self.on_log(level, message)

    def redact(self, text: str) -> str:
        return self.keys.redact(text)
