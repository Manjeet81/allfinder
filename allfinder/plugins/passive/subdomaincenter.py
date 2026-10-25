"""subdomain.center (ARPSyndicate) free API."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.subdomain.center/"


class SubdomainCenter(HttpPlugin):
    name = "subdomaincenter"
    kind = SourceKind.PASSIVE
    description = "api.subdomain.center"
    rate_limit = 0.5
    retries = 3
    weight = 6
    tags = ("free", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.get_json(ctx, API, params={"domain": target.root}, ok=[404])
        if isinstance(data, list):
            for f in self.findings_from_values([v for v in data if isinstance(v, str)], target):
                yield f
