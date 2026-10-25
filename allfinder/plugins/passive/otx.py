"""AlienVault OTX: passive DNS + URL list (free, key optional)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/{section}"
MAX_URL_PAGES = 50


class Otx(HttpPlugin):
    name = "otx"
    kind = SourceKind.PASSIVE
    description = "AlienVault OTX passive DNS and URL list"
    key_provider = "otx"
    rate_limit = 2.0
    recursive = True
    weight = 8
    tags = ("free", "threatintel", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        key = self.key(ctx)
        headers = {"X-OTX-API-KEY": key} if key else {}
        seen: set[str] = set()

        data = await self.get_json(
            ctx,
            API.format(domain=target.root, section="passive_dns"),
            headers=headers,
            key=key,
            ok=[404],
        )
        for rec in (data or {}).get("passive_dns", []) if isinstance(data, dict) else []:
            if not isinstance(rec, dict):
                continue
            host = rec.get("hostname")
            addr = rec.get("address")
            rtype = str(rec.get("record_type") or "").upper()
            ips = [addr] if addr and rtype in ("A", "AAAA") else []
            cname = addr if rtype == "CNAME" else None
            f = self.finding(host, ips=ips, cname=cname)
            if f and f.hostname not in seen:
                seen.add(f.hostname)
                yield f

        for page in range(1, MAX_URL_PAGES + 1):
            data = await self.get_json(
                ctx,
                API.format(domain=target.root, section="url_list"),
                params={"limit": 500, "page": page},
                headers=headers,
                key=key,
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            urls = data.get("url_list") or []
            values = []
            for u in urls:
                if isinstance(u, dict):
                    values.append(u.get("hostname") or u.get("url"))
            for f in self.findings_from_values(values, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            if not data.get("has_next") or not urls:
                break
