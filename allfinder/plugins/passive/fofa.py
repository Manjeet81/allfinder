"""FOFA search API (key ``email:key`` required)."""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://fofa.info/api/v1/search/all"
MAX_PAGES = 10


def _auth(key: str) -> dict[str, object]:
    if ":" in key:
        email, k = key.split(":", 1)
        return {"params": {"email": email, "key": k}}
    return {"params": {"key": key}}


class Fofa(HttpPlugin):
    name = "fofa"
    kind = SourceKind.PASSIVE
    description = "FOFA search (domain=...)"
    key_provider = "fofa"
    requires = {"api_keys": ["fofa"]}
    rate_limit = 0.5
    weight = 6
    tags = ("keyed", "search")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        q = base64.b64encode(f'domain="{target.root}"'.encode()).decode()
        seen: set[str] = set()
        for page in range(1, MAX_PAGES + 1):
            data = await self.keyed_json(
                ctx,
                API,
                auth=_auth,
                params={"qbase64": q, "size": 10000, "page": page, "fields": "host,ip"},
            )
            if not isinstance(data, dict):
                break
            if data.get("error"):
                raise RuntimeError(str(data.get("errmsg") or "fofa error"))
            results = data.get("results") or []
            for row in results:
                if isinstance(row, (list, tuple)) and row:
                    host = str(row[0])
                    ip = str(row[1]) if len(row) > 1 and row[1] else None
                    f = self.finding(host, ips=[ip] if ip else None)
                else:
                    f = self.finding(str(row))
                if f and f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            size = int(data.get("size") or 0)
            if not results or page * 10000 >= size:
                break
