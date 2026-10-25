"""HackerTarget hostsearch (free, ~50 queries/day per IP)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.hackertarget.com/hostsearch/"


class HackerTarget(HttpPlugin):
    name = "hackertarget"
    kind = SourceKind.PASSIVE
    description = "HackerTarget hostsearch API"
    key_provider = "hackertarget"
    rate_limit = 1.0
    recursive = True
    weight = 7
    tags = ("free", "dns", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        params = {"q": target.root}
        key = self.key(ctx)
        if key:
            params["apikey"] = key
        text = await self.get_text(ctx, API, params=params, key=key)
        low = text.lower()
        if "api count exceeded" in low or low.startswith("error"):
            raise RuntimeError(text.strip()[:120])
        for line in text.splitlines():
            parts = line.split(",")
            host = parts[0].strip()
            ips = [p.strip() for p in parts[1:] if p.strip()]
            f = self.finding(host, ips=ips)
            if f:
                yield f
