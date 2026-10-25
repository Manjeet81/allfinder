"""VirusTotal v3 ``/domains/{d}/subdomains`` (key required, paginated)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
MAX_PAGES = 200


class VirusTotal(HttpPlugin):
    name = "virustotal"
    kind = SourceKind.PASSIVE
    description = "VirusTotal v3 domain subdomains"
    key_provider = "virustotal"
    requires = {"api_keys": ["virustotal"]}
    rate_limit = 0.25
    weight = 7
    tags = ("keyed", "threatintel")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        url: str | None = API.format(domain=target.root)
        params: dict[str, object] | None = {"limit": 40}
        for _ in range(MAX_PAGES):
            if not url:
                break
            data = await self.keyed_json(
                ctx, url, auth=lambda k: {"headers": {"x-apikey": k}}, params=params, ok=[404]
            )
            params = None  # the "next" link already carries the cursor
            if not isinstance(data, dict):
                break
            for item in data.get("data") or []:
                if not isinstance(item, dict):
                    continue
                ips: list[str] = []
                cname = None
                attrs = item.get("attributes") or {}
                for rec in attrs.get("last_dns_records") or []:
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("type") in ("A", "AAAA") and rec.get("value"):
                        ips.append(str(rec["value"]))
                    elif rec.get("type") == "CNAME" and rec.get("value"):
                        cname = str(rec["value"])
                f = self.finding(item.get("id"), ips=ips, cname=cname)
                if f:
                    yield f
            url = (data.get("links") or {}).get("next")
