"""Hunter.how search API (key required)."""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.hunter.how/search"
MAX_PAGES = 20


class HunterHow(HttpPlugin):
    name = "hunter"
    kind = SourceKind.PASSIVE
    description = "hunter.how search (domain=...)"
    key_provider = "hunter"
    requires = {"api_keys": ["hunter"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "search")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        q = base64.urlsafe_b64encode(f'domain="{target.root}"'.encode()).decode()
        end = datetime.now(UTC).date()
        start = end - timedelta(days=365)
        seen: set[str] = set()
        for page in range(1, MAX_PAGES + 1):
            data = await self.keyed_json(
                ctx,
                API,
                auth=lambda k: {"params": {"api-key": k}},
                params={
                    "query": q,
                    "page": page,
                    "page_size": 100,
                    "start_time": start.isoformat(),
                    "end_time": end.isoformat(),
                },
            )
            if not isinstance(data, dict):
                break
            if data.get("code") not in (200, "200", None):
                raise RuntimeError(str(data.get("message") or f"hunter error {data.get('code')}"))
            lst = (data.get("data") or {}).get("list") or []
            for item in lst:
                if not isinstance(item, dict):
                    continue
                ip = item.get("ip")
                f = self.finding(item.get("domain"), ips=[ip] if isinstance(ip, str) else None)
                if f and f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            total = int((data.get("data") or {}).get("total") or 0)
            if not lst or page * 100 >= total:
                break
