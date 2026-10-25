"""DNSRepo (dnsrepo.noc.org).  Works without a key for small domains."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

URL = "https://dnsrepo.noc.org/"


class DnsRepo(HttpPlugin):
    name = "dnsrepo"
    kind = SourceKind.PASSIVE
    description = "dnsrepo.noc.org passive DNS"
    key_provider = "dnsrepo"
    rate_limit = 1.0
    weight = 3
    tags = ("free", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        key = self.key(ctx)
        params: dict[str, str] = {"domain": target.root}
        if key:
            params["apikey"] = key
        if key:
            data = await self.get_json(
                ctx, "https://dnsarchive.net/api/", params=params, key=key, ok=[404]
            )
            values: list[str] = []
            if isinstance(data, list):
                for rec in data:
                    if isinstance(rec, dict) and rec.get("domain"):
                        values.append(str(rec["domain"]))
            for f in self.findings_from_values(values, target):
                yield f
            return
        html = await self.get_text(ctx, URL, params=params, ok=[404])
        for f in self.findings_from_text(html, target):
            yield f
