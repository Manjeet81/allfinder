"""Censys Search v2: certificates (names) + hosts (key ``id:secret`` required)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin
from allfinder.utils.text import iter_strings

CERTS = "https://search.censys.io/api/v2/certificates/search"
HOSTS = "https://search.censys.io/api/v2/hosts/search"
MAX_PAGES = 20


def _basic(key: str) -> dict[str, object]:
    if ":" not in key:
        raise ValueError("censys key must be 'api_id:api_secret'")
    uid, secret = key.split(":", 1)
    return {"auth": httpx.BasicAuth(uid, secret)}


class Censys(HttpPlugin):
    name = "censys"
    kind = SourceKind.PASSIVE
    description = "Censys Search v2 certificates + hosts"
    key_provider = "censys"
    requires = {"api_keys": ["censys"]}
    rate_limit = 0.4
    weight = 7
    tags = ("keyed", "ct")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for url, query in (
            (CERTS, f"names: {target.root}"),
            (HOSTS, f"services.tls.certificates.leaf_data.names: {target.root}"),
        ):
            cursor: str | None = None
            for _ in range(MAX_PAGES):
                params: dict[str, object] = {"q": query, "per_page": 100}
                if cursor:
                    params["cursor"] = cursor
                data = await self.keyed_json(ctx, url, auth=_basic, params=params, ok=[404])
                if not isinstance(data, dict):
                    break
                result = data.get("result") or {}
                hits = result.get("hits") or []
                values: list[str] = []
                for hit in hits:
                    if not isinstance(hit, dict):
                        continue
                    if url is CERTS:
                        values.extend(n for n in hit.get("names") or [] if isinstance(n, str))
                    else:
                        values.extend(iter_strings(hit))
                for f in self.findings_from_values(values, target):
                    if f.hostname not in seen:
                        seen.add(f.hostname)
                        yield f
                cursor = (result.get("links") or {}).get("next") or None
                if not cursor or not hits:
                    break
