"""Wayback Machine CDX index (free).  Streams the (large) response."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://web.archive.org/cdx/search/cdx"
MAX_LINES = 2_000_000


class Wayback(HttpPlugin):
    name = "wayback"
    kind = SourceKind.PASSIVE
    description = "Wayback Machine CDX index (archived URLs)"
    default_timeout = 300
    rate_limit = 1.0
    weight = 5
    tags = ("free", "archives")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        params = {
            "url": f"*.{target.root}/*",
            "output": "txt",
            "fl": "original",
            "collapse": "urlkey",
        }
        async for line in self.stream_lines(ctx, API, params=params, max_lines=MAX_LINES, ok=[404]):
            for f in self.findings_from_values([line], target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
