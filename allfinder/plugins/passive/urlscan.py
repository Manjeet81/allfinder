"""urlscan.io search API (free tier; key raises limits)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://urlscan.io/api/v1/search/"
MAX_PAGES = 20


class UrlScan(HttpPlugin):
    name = "urlscan"
    kind = SourceKind.PASSIVE
    description = "urlscan.io search (page.domain)"
    key_provider = "urlscan"
    rate_limit = 1.0
    weight = 5
    tags = ("free", "archives", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        key = self.key(ctx)
        headers = {"API-Key": key} if key else {}
        seen: set[str] = set()
        search_after: list[object] | None = None
        for _ in range(MAX_PAGES):
            params: dict[str, object] = {"q": f"domain:{target.root}", "size": 10000}
            if search_after:
                params["search_after"] = ",".join(str(x) for x in search_after)
            data = await self.get_json(ctx, API, params=params, headers=headers, key=key)
            if not isinstance(data, dict):
                break
            results = data.get("results") or []
            values: list[str] = []
            for r in results:
                if not isinstance(r, dict):
                    continue
                for section in ("page", "task"):
                    sec = r.get(section) or {}
                    if isinstance(sec, dict):
                        values.append(sec.get("domain") or "")
                        values.append(sec.get("url") or "")
            for f in self.findings_from_values(values, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            if not data.get("has_more") or not results:
                break
            last = results[-1]
            search_after = last.get("sort") if isinstance(last, dict) else None
            if not search_after:
                break
