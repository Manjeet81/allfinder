"""BinaryEdge subdomain query (key required, paginated)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
MAX_PAGES = 50


class BinaryEdge(HttpPlugin):
    name = "binaryedge"
    kind = SourceKind.PASSIVE
    description = "BinaryEdge domains/subdomain"
    key_provider = "binaryedge"
    requires = {"api_keys": ["binaryedge"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        for page in range(1, MAX_PAGES + 1):
            data = await self.keyed_json(
                ctx,
                API.format(domain=target.root),
                auth=lambda k: {"headers": {"X-Key": k}},
                params={"page": page},
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            events = data.get("events") or []
            for f in self.findings_from_values([e for e in events if isinstance(e, str)], target):
                yield f
            total = int(data.get("total") or 0)
            pagesize = int(data.get("pagesize") or len(events) or 1)
            if not events or page * pagesize >= total:
                break
