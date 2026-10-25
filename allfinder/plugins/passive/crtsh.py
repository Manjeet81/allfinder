"""crt.sh certificate-transparency search (free, no key)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://crt.sh/"


class CrtSh(HttpPlugin):
    name = "crtsh"
    kind = SourceKind.PASSIVE
    description = "crt.sh certificate transparency log search"
    default_timeout = 180
    rate_limit = 1.0
    weight = 10
    recursive = True
    tags = ("free", "ct", "quick")
    retries = 4  # crt.sh answers 502/503 a lot; be patient

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for query in (f"%.{target.root}", target.root):
            data = await self.get_json(
                ctx,
                API,
                params={"q": query, "output": "json"},
                ok=[404],
            )
            if not isinstance(data, list):
                continue
            values: list[str] = []
            for row in data:
                if not isinstance(row, dict):
                    continue
                for key in ("name_value", "common_name"):
                    v = row.get(key)
                    if isinstance(v, str):
                        values.append(v)
            for f in self.findings_from_values(values, target, in_scope_only=False):
                if f.hostname in seen:
                    continue
                seen.add(f.hostname)
                yield f
            if query == f"%.{target.root}" and seen:
                # the wildcard query already includes the apex when certs exist for it
                if target.root in seen:
                    break
