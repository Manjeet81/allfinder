"""Shodan ``/dns/domain/{d}`` (key required, paginated)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.shodan.io/dns/domain/{domain}"
MAX_PAGES = 50


class Shodan(HttpPlugin):
    name = "shodan"
    kind = SourceKind.PASSIVE
    description = "Shodan DNS domain data"
    key_provider = "shodan"
    requires = {"api_keys": ["shodan"]}
    rate_limit = 1.0
    weight = 7
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(1, MAX_PAGES + 1):
            data = await self.keyed_json(
                ctx,
                API.format(domain=target.root),
                auth=lambda k: {"params": {"key": k}},
                params={"page": page},
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            records: dict[str, Finding] = {}
            for rec in data.get("data") or []:
                if not isinstance(rec, dict):
                    continue
                sub = rec.get("subdomain") or ""
                host = f"{sub}.{target.root}" if sub else target.root
                f = records.get(host) or self.finding(host)
                if f is None:
                    continue
                rtype, value = rec.get("type"), rec.get("value")
                if rtype in ("A", "AAAA") and value:
                    f.ips.append(str(value))
                elif rtype == "CNAME" and value and not f.cname:
                    f.cname = str(value)
                records[f.hostname] = f
            for sub in data.get("subdomains") or []:
                if isinstance(sub, str):
                    f = self.finding(f"{sub}.{target.root}")
                    if f and f.hostname not in records:
                        records[f.hostname] = f
            for host, f in records.items():
                if host not in seen:
                    seen.add(host)
                    yield f
            if not data.get("more"):
                break
