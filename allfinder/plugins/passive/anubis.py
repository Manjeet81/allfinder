"""Anubis-DB (jldc.me) free subdomain database."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://jldc.me/anubis/subdomains/{domain}"


class Anubis(HttpPlugin):
    name = "anubis"
    kind = SourceKind.PASSIVE
    description = "Anubis-DB (jldc.me)"
    rate_limit = 2.0
    recursive = True
    weight = 6
    tags = ("free", "dns", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.get_json(ctx, API.format(domain=target.root), ok=[404, 300])
        if isinstance(data, list):
            for f in self.findings_from_values([v for v in data if isinstance(v, str)], target):
                yield f
