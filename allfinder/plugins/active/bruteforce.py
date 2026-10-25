"""Brute force: generate ``word.root`` candidates from a wordlist, then resolve.

Uses puredns/massdns when available, else the native resolver pool with
trusted re-validation.  Tier is chosen with ``--brute small|medium|large``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from pathlib import Path

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.core.wordlists import iter_lines, wordlist_for_tier
from allfinder.plugins.base import Plugin, SkipPlugin

CHUNK = 100_000


class BruteForce(Plugin):
    name = "bruteforce"
    kind = SourceKind.ACTIVE
    description = "wordlist brute force (puredns/massdns or native) -> resolve"
    default_timeout = 7200
    weight = 2
    recursive = True
    tags = ("active", "brute")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        tier = ctx.options.brute
        if tier in ("", "none"):
            return
        path = wordlist_for_tier(ctx.config, tier)
        if path is None:
            raise SkipPlugin(f"wordlist for --brute {tier} not found (run: allfinder update)")
        from allfinder.core.dns.massresolve import resolve_hosts

        ctx.log.info("brute force %s under %s with %s", tier, target.root, path.name)
        for chunk in _chunked(_candidates(path, target.root), CHUNK):
            if ctx.cancelled or ctx.out_of_time():
                break
            fresh = [c for c in chunk if c not in ctx.store]
            if not fresh:
                continue
            results = await resolve_hosts(ctx, fresh, root=target.root, validate_hits=True)
            for host, res in results.items():
                if res.resolved and not res.wildcard:
                    yield Finding(
                        host, self.name, ips=res.ips, cname=res.cname[0] if res.cname else None
                    )


def _candidates(path: Path, root: str) -> Iterable[str]:
    seen: set[str] = set()
    for word in iter_lines(path):
        word = word.strip().strip(".").lower()
        if not word or " " in word:
            continue
        host = f"{word}.{root}" if not word.endswith("." + root) and word != root else word
        if host not in seen:
            seen.add(host)
            yield host


def _chunked(it: Iterable[str], size: int) -> Iterable[list[str]]:
    buf: list[str] = []
    for item in it:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf
