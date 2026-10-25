"""ZoomEye domain search (key required)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.zoomeye.org/domain/search"
MAX_PAGES = 50


class ZoomEye(HttpPlugin):
    name = "zoomeye"
    kind = SourceKind.PASSIVE
    description = "ZoomEye domain/search (type=1)"
    key_provider = "zoomeye"
    requires = {"api_keys": ["zoomeye"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "search")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        total = None
        for page in range(1, MAX_PAGES + 1):
            data = await self.keyed_json(
                ctx,
                API,
                auth=lambda k: {"headers": {"API-KEY": k}},
                params={"q": target.root, "type": 1, "page": page},
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            items = data.get("list") or []
            for item in items:
                if not isinstance(item, dict):
                    continue
                ip = item.get("ip")
                ips = [ip] if isinstance(ip, str) else [i for i in ip or [] if isinstance(i, str)]
                f = self.finding(item.get("name"), ips=ips)
                if f and f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            total = data.get("total", total)
            if not items or (isinstance(total, int) and len(seen) >= total):
                break
