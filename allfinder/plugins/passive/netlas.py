"""Netlas domains search (key required)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://app.netlas.io/api/domains/"
PAGE = 20
MAX_PAGES = 100


class Netlas(HttpPlugin):
    name = "netlas"
    kind = SourceKind.PASSIVE
    description = "Netlas domains index"
    key_provider = "netlas"
    requires = {"api_keys": ["netlas"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(MAX_PAGES):
            data = await self.keyed_json(
                ctx,
                API,
                auth=lambda k: {"headers": {"X-API-Key": k}},
                params={
                    "q": f"domain:*.{target.root}",
                    "source_type": "include",
                    "start": page * PAGE,
                    "fields": "domain,a,cname",
                },
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            items = data.get("items") or []
            for item in items:
                d = item.get("data") if isinstance(item, dict) else None
                if not isinstance(d, dict):
                    continue
                a = d.get("a") or []
                cn = d.get("cname") or []
                f = self.finding(
                    d.get("domain"),
                    ips=[x for x in a if isinstance(x, str)],
                    cname=cn[0] if isinstance(cn, list) and cn else None,
                )
                if f and f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            if len(items) < PAGE:
                break
