"""ThreatMiner domain subdomains API (free)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.threatminer.org/v2/domain.php"


class ThreatMiner(HttpPlugin):
    name = "threatminer"
    kind = SourceKind.PASSIVE
    description = "ThreatMiner subdomains (rt=5)"
    rate_limit = 0.2  # documented 10 req/min
    weight = 4
    tags = ("free", "threatintel")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.get_json(ctx, API, params={"q": target.root, "rt": 5}, ok=[404])
        if not isinstance(data, dict):
            return
        results = data.get("results") or []
        for f in self.findings_from_values([r for r in results if isinstance(r, str)], target):
            yield f
