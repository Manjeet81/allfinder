"""Columbus Project (columbus.elmasy.com) free CT-derived database."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://columbus.elmasy.com/api/lookup/{domain}"


class Columbus(HttpPlugin):
    name = "columbus"
    kind = SourceKind.PASSIVE
    description = "Columbus Project lookup API"
    rate_limit = 2.0
    recursive = True
    weight = 6
    tags = ("free", "ct", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.get_json(
            ctx,
            API.format(domain=target.root),
            params={"days": -1},
            headers={"Accept": "application/json"},
            ok=[404],
        )
        if not isinstance(data, list):
            return
        values: list[str] = []
        for item in data:
            if not isinstance(item, str):
                continue
            item = item.strip().strip(".")
            if not item:
                values.append(target.root)
            elif item == target.root or item.endswith("." + target.root):
                values.append(item)
            else:
                values.append(f"{item}.{target.root}")  # API returns label prefixes
        for f in self.findings_from_values(values, target):
            yield f
