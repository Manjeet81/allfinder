"""ShrewdEye plain-text subdomain export (free)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

URL = "https://shrewdeye.app/domains/{domain}.txt"


class ShrewdEye(HttpPlugin):
    name = "shrewdeye"
    kind = SourceKind.PASSIVE
    description = "shrewdeye.app domain export"
    rate_limit = 1.0
    weight = 3
    tags = ("free", "dns", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        text = await self.get_text(ctx, URL.format(domain=target.root), ok=[404])
        for f in self.findings_from_values(text.splitlines(), target):
            yield f
