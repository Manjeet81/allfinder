"""360 Quake service search (key required)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin
from allfinder.utils.text import dig

API = "https://quake.360.net/api/v3/search/quake_service"
SIZE = 500
MAX_PAGES = 20


class Quake(HttpPlugin):
    name = "quake"
    kind = SourceKind.PASSIVE
    description = "360 Quake service search"
    key_provider = "quake"
    requires = {"api_keys": ["quake"]}
    rate_limit = 1.0
    weight = 4
    tags = ("keyed", "search")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(MAX_PAGES):
            data = await self.keyed_json(
                ctx,
                API,
                method="POST",
                auth=lambda k: {"headers": {"X-QuakeToken": k}},
                json={
                    "query": f'domain:"{target.root}"',
                    "start": page * SIZE,
                    "size": SIZE,
                    "include": ["service.http.host", "ip"],
                },
            )
            if not isinstance(data, dict):
                break
            if data.get("code") not in (0, "0", None):
                raise RuntimeError(str(data.get("message") or f"quake error {data.get('code')}"))
            items = data.get("data") or []
            for item in items:
                host = dig(item, "service", "http", "host")
                ip = item.get("ip") if isinstance(item, dict) else None
                f = self.finding(host, ips=[ip] if isinstance(ip, str) else None)
                if f and f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            total = int(dig(data, "meta", "pagination", "total", default=0) or 0)
            if not items or (page + 1) * SIZE >= total:
                break
