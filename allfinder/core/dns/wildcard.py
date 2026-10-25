"""Multi-level wildcard detection and filtering.

For the root and every intermediate parent of a candidate
(``a.b.example.com`` -> ``*.b.example.com``, ``*.example.com``) we resolve
a few random labels and remember the answer set.  A candidate whose answers
are a subset of its parent's wildcard answers is *wildcard-only*.
"""

from __future__ import annotations

import asyncio
import random
import string
from collections.abc import Awaitable, Callable, Iterable

from allfinder.core.models import Resolution
from allfinder.core.normalize import in_scope, parents

Resolver = Callable[[str], Awaitable[Resolution]]

_ALPHABET = string.ascii_lowercase + string.digits


def random_label(length: int = 12) -> str:
    return "".join(random.choices(_ALPHABET, k=length))


def answer_set(res: Resolution) -> frozenset[str]:
    """Normalized answers (IPs + CNAME targets) used for wildcard comparison."""
    items = {ip.lower() for ip in res.ips}
    items.update(c.lower().rstrip(".") for c in res.cname)
    return frozenset(items)


class WildcardDetector:
    """Detects wildcard zones lazily and classifies resolutions."""

    def __init__(self, resolve: Resolver, *, tests: int = 3, concurrency: int = 20) -> None:
        self._resolve = resolve
        self.tests = max(1, tests)
        self._sem = asyncio.Semaphore(concurrency)
        self._zones: dict[str, frozenset[str] | None] = {}  # parent -> answers (None = none)
        self._locks: dict[str, asyncio.Lock] = {}

    @property
    def wildcard_zones(self) -> dict[str, frozenset[str]]:
        return {z: a for z, a in self._zones.items() if a}

    async def probe(self, zone: str) -> frozenset[str] | None:
        """Return the wildcard answer set for ``*.zone`` (cached), or ``None``."""
        if zone in self._zones:
            return self._zones[zone]
        lock = self._locks.setdefault(zone, asyncio.Lock())
        async with lock:
            if zone in self._zones:
                return self._zones[zone]
            answers: set[str] = set()
            hits = 0

            async def one() -> None:
                nonlocal hits
                async with self._sem:
                    res = await self._resolve(f"{random_label()}.{zone}")
                if res.resolved:
                    hits += 1
                    answers.update(answer_set(res))

            await asyncio.gather(*(one() for _ in range(self.tests)), return_exceptions=True)
            result = frozenset(answers) if hits else None
            self._zones[zone] = result
            return result

    async def probe_all(self, hosts: Iterable[str], root: str) -> None:
        """Probe every parent zone appearing in *hosts* (deduplicated)."""
        zones: set[str] = set()
        for h in hosts:
            if not in_scope(h, root):
                continue
            zones.update(parents(h, root))
        await asyncio.gather(
            *(self.probe(z) for z in sorted(zones, key=len)), return_exceptions=True
        )

    async def is_wildcard_only(self, res: Resolution, root: str) -> bool:
        """``True`` when every answer of *res* is explained by a parent wildcard."""
        if not res.resolved or not in_scope(res.hostname, root) or res.hostname == root:
            return False
        mine = answer_set(res)
        if not mine:
            return False
        for zone in parents(res.hostname, root):
            wc = await self.probe(zone)
            if wc and mine <= wc:
                return True
        return False

    def classify_sync(self, res: Resolution, root: str) -> bool:
        """Like :meth:`is_wildcard_only` but only with already-probed zones."""
        if not res.resolved or not in_scope(res.hostname, root) or res.hostname == root:
            return False
        mine = answer_set(res)
        if not mine:
            return False
        for zone in parents(res.hostname, root):
            wc = self._zones.get(zone)
            if wc and mine <= wc:
                return True
        return False


def filter_wildcards(
    resolutions: Iterable[Resolution],
    wildcard_answers: dict[str, frozenset[str]],
    root: str,
) -> list[Resolution]:
    """Pure helper: flag ``wildcard=True`` on resolutions explained by *wildcard_answers*."""
    out: list[Resolution] = []
    for res in resolutions:
        res.wildcard = False
        if res.resolved and in_scope(res.hostname, root) and res.hostname != root:
            mine = answer_set(res)
            for zone in parents(res.hostname, root):
                wc = wildcard_answers.get(zone)
                if wc and mine and mine <= wc:
                    res.wildcard = True
                    break
        out.append(res)
    return out
