"""PassiveTotal / RiskIQ (legacy), DNSDB (Farsight), RedHunt Labs, CriminalIP, DNSDumpster."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin
from allfinder.utils.text import iter_strings


def _basic_user_key(key: str) -> dict[str, object]:
    if ":" not in key:
        raise ValueError("key must be 'user:key'")
    user, secret = key.split(":", 1)
    return {"auth": httpx.BasicAuth(user, secret)}


class PassiveTotal(HttpPlugin):
    name = "passivetotal"
    kind = SourceKind.PASSIVE
    description = "RiskIQ PassiveTotal enrichment/subdomains (legacy API)"
    key_provider = "passivetotal"
    requires = {"api_keys": ["passivetotal"]}
    rate_limit = 1.0
    weight = 3
    tags = ("keyed", "dns", "legacy")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            "https://api.riskiq.net/pt/v2/enrichment/subdomains",
            auth=_basic_user_key,
            params={"query": target.root},
            ok=[404],
        )
        subs = (data or {}).get("subdomains") or [] if isinstance(data, dict) else []
        values = [f"{s}.{target.root}" for s in subs if isinstance(s, str)]
        for f in self.findings_from_values(values, target):
            yield f


class DnsDb(HttpPlugin):
    name = "dnsdb"
    kind = SourceKind.PASSIVE
    description = "Farsight DNSDB rrset lookup (*.domain)"
    key_provider = "dnsdb"
    requires = {"api_keys": ["dnsdb"]}
    default_timeout = 300
    rate_limit = 1.0
    weight = 6
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        resp = await self.keyed_request(
            ctx,
            "GET",
            f"https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{target.root}",
            auth=lambda k: {"headers": {"X-API-Key": k, "Accept": "application/x-ndjson"}},
            params={"limit": 0},
            ok=[404],
        )
        seen: set[str] = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line).get("obj")
            except (ValueError, AttributeError):
                continue
            if not isinstance(obj, dict):
                continue
            rtype = str(obj.get("rrtype") or "").upper()
            rdata = obj.get("rdata") or []
            rdata = [rdata] if isinstance(rdata, str) else [r for r in rdata if isinstance(r, str)]
            rdata = [str(r) for r in rdata]
            ips: list[str] = rdata if rtype in ("A", "AAAA") else []
            cname = rdata[0].rstrip(".") if rtype == "CNAME" and rdata else None
            f = self.finding(obj.get("rrname"), ips=ips, cname=cname)
            if f and f.hostname not in seen:
                seen.add(f.hostname)
                yield f


class RedHunt(HttpPlugin):
    name = "redhunt"
    kind = SourceKind.PASSIVE
    description = "RedHunt Labs recon API subdomains"
    key_provider = "redhunt"
    requires = {"api_keys": ["redhunt"]}
    rate_limit = 1.0
    weight = 4
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        page = 1
        seen: set[str] = set()
        while page <= 100:
            data = await self.keyed_json(
                ctx,
                "https://reconapi.redhuntlabs.com/community/v1/domains/subdomains",
                auth=lambda k: {"headers": {"X-BLOBR-KEY": k}},
                params={"domain": target.root, "page_size": 1000, "page": page},
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            subs = data.get("subdomains") or []
            for f in self.findings_from_values([s for s in subs if isinstance(s, str)], target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            meta = data.get("metadata") or {}
            total = int(meta.get("result_count") or 0)
            if not subs or page * 1000 >= total:
                break
            page += 1


class CriminalIp(HttpPlugin):
    name = "criminalip"
    kind = SourceKind.PASSIVE
    description = "CriminalIP domain reports (hostnames mined from report JSON)"
    key_provider = "criminalip"
    requires = {"api_keys": ["criminalip"]}
    rate_limit = 1.0
    weight = 3
    tags = ("keyed", "threatintel")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            "https://api.criminalip.io/v1/domain/reports",
            auth=lambda k: {"headers": {"x-api-key": k}},
            params={"query": target.root, "offset": 0},
            ok=[404],
        )
        if isinstance(data, dict) and data.get("status") not in (200, None):
            raise RuntimeError(str(data.get("message") or "criminalip error"))
        for f in self.findings_from_values(list(iter_strings(data)), target):
            yield f


class DnsDumpster(HttpPlugin):
    name = "dnsdumpster"
    kind = SourceKind.PASSIVE
    description = "DNSDumpster API (A/CNAME/MX/NS records)"
    key_provider = "dnsdumpster"
    requires = {"api_keys": ["dnsdumpster"]}
    rate_limit = 0.5
    weight = 6
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(1, 6):
            params = {"page": page} if page > 1 else None
            data = await self.keyed_json(
                ctx,
                f"https://api.dnsdumpster.com/domain/{target.root}",
                auth=lambda k: {"headers": {"X-API-Key": k}},
                params=params,
                ok=[404],
            )
            if not isinstance(data, dict):
                break
            new = 0
            for section in ("a", "cname", "mx", "ns"):
                for rec in data.get(section) or []:
                    if not isinstance(rec, dict):
                        continue
                    ips = [
                        str(i["ip"])
                        for i in rec.get("ips") or []
                        if isinstance(i, dict) and i.get("ip")
                    ]
                    f = self.finding(rec.get("host"), ips=ips, cname=rec.get("target"))
                    if f and f.hostname not in seen:
                        seen.add(f.hostname)
                        new += 1
                        yield f
            if new == 0 or not data.get("total_a_recs") or len(data.get("a") or []) < 200:
                break
