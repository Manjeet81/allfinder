"""Digitorus certificatedetails.com (HTML, free)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

URL = "https://certificatedetails.com/{domain}"


class Digitorus(HttpPlugin):
    name = "digitorus"
    kind = SourceKind.PASSIVE
    description = "certificatedetails.com (Digitorus)"
    rate_limit = 1.0
    weight = 3
    tags = ("free", "ct")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        html = await self.get_text(ctx, URL.format(domain=target.root), ok=[404])
        for f in self.findings_from_text(html, target):
            yield f
