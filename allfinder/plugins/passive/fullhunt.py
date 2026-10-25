"""FullHunt, LeakIX, BeVigil, Chaos, WhoisXML, C99, ThreatBook: single-call keyed APIs."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin
from allfinder.utils.text import dig


class FullHunt(HttpPlugin):
    name = "fullhunt"
    kind = SourceKind.PASSIVE
    description = "FullHunt domain subdomains"
    key_provider = "fullhunt"
    requires = {"api_keys": ["fullhunt"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            f"https://fullhunt.io/api/v1/domain/{target.root}/subdomains",
            auth=lambda k: {"headers": {"X-API-KEY": k}},
            ok=[404],
        )
        hosts = (data or {}).get("hosts") or [] if isinstance(data, dict) else []
        for f in self.findings_from_values([h for h in hosts if isinstance(h, str)], target):
            yield f


class LeakIX(HttpPlugin):
    name = "leakix"
    kind = SourceKind.PASSIVE
    description = "LeakIX subdomains API"
    key_provider = "leakix"
    requires = {"api_keys": ["leakix"]}
    rate_limit = 1.0
    weight = 4
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            f"https://leakix.net/api/subdomains/{target.root}",
            auth=lambda k: {"headers": {"api-key": k, "Accept": "application/json"}},
            ok=[404],
        )
        if not isinstance(data, list):
            return
        for item in data:
            host = item.get("subdomain") if isinstance(item, dict) else item
            f = self.finding(host if isinstance(host, str) else None)
            if f:
                yield f


class BeVigil(HttpPlugin):
    name = "bevigil"
    kind = SourceKind.PASSIVE
    description = "BeVigil OSINT (mobile apps) subdomains"
    key_provider = "bevigil"
    requires = {"api_keys": ["bevigil"]}
    rate_limit = 1.0
    weight = 4
    tags = ("keyed", "mobile")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            f"https://osint.bevigil.com/api/{target.root}/subdomains/",
            auth=lambda k: {"headers": {"X-Access-Token": k}},
            ok=[404],
        )
        subs = (data or {}).get("subdomains") or [] if isinstance(data, dict) else []
        for f in self.findings_from_values([s for s in subs if isinstance(s, str)], target):
            yield f


class Chaos(HttpPlugin):
    name = "chaos"
    kind = SourceKind.PASSIVE
    description = "projectdiscovery Chaos dataset (native)"
    key_provider = "chaos"
    requires = {"api_keys": ["chaos"]}
    rate_limit = 1.0
    weight = 8
    recursive = True
    tags = ("keyed", "dns", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            f"https://dns.projectdiscovery.io/dns/{target.root}/subdomains",
            auth=lambda k: {"headers": {"Authorization": k}},
            ok=[404],
        )
        subs = (data or {}).get("subdomains") or [] if isinstance(data, dict) else []
        values = [
            f"{s}.{target.root}" if s and s != "*" else target.root
            for s in subs
            if isinstance(s, str)
        ]
        for f in self.findings_from_values(values, target):
            yield f


class WhoisXml(HttpPlugin):
    name = "whoisxml"
    kind = SourceKind.PASSIVE
    description = "WhoisXML API subdomains lookup"
    key_provider = "whoisxml"
    requires = {"api_keys": ["whoisxml"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            "https://subdomains.whoisxmlapi.com/api/v1",
            auth=lambda k: {"params": {"apiKey": k}},
            params={"domainName": target.root},
        )
        records = dig(data, "result", "records", default=[]) or []
        values = [r.get("domain") for r in records if isinstance(r, dict)]
        for f in self.findings_from_values(values, target):
            yield f


class C99(HttpPlugin):
    name = "c99"
    kind = SourceKind.PASSIVE
    description = "C99.nl subdomain finder"
    key_provider = "c99"
    requires = {"api_keys": ["c99"]}
    rate_limit = 1.0
    weight = 5
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            "https://api.c99.nl/subdomainfinder",
            auth=lambda k: {"params": {"key": k}},
            params={"domain": target.root, "json": ""},
        )
        if not isinstance(data, dict):
            return
        if data.get("success") is False:
            raise RuntimeError(str(data.get("error") or "c99 error"))
        for item in data.get("subdomains") or []:
            if isinstance(item, dict):
                ip = item.get("ip")
                f = self.finding(
                    item.get("subdomain"), ips=[ip] if isinstance(ip, str) and ip else None
                )
            else:
                f = self.finding(str(item))
            if f:
                yield f


class ThreatBook(HttpPlugin):
    name = "threatbook"
    kind = SourceKind.PASSIVE
    description = "ThreatBook sub_domains"
    key_provider = "threatbook"
    requires = {"api_keys": ["threatbook"]}
    rate_limit = 1.0
    weight = 4
    tags = ("keyed", "threatintel")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            "https://api.threatbook.cn/v3/domain/sub_domains",
            auth=lambda k: {"params": {"apikey": k}},
            params={"resource": target.root},
        )
        if isinstance(data, dict) and data.get("response_code") not in (0, None):
            raise RuntimeError(str(data.get("verbose_msg") or "threatbook error"))
        subs = dig(data, "data", "sub_domains", "data", default=[]) or []
        for f in self.findings_from_values([s for s in subs if isinstance(s, str)], target):
            yield f
