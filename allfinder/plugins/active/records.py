"""DNS record mining: AXFR, NSEC/NSEC3 walk, SOA/NS/MX/TXT/SPF/SRV and CNAME chains.

These reveal hostnames that no passive source lists: zone transfers dump the
whole zone, SPF ``include:`` chains name mail infra, CNAME targets point at
third-party and internal hosts.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import dns.zone

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import Plugin

if TYPE_CHECKING:
    from allfinder.core.dns.resolver_pool import ResolverPool

_SPF_INCLUDE = re.compile(r"(?:include:|redirect=|exists:|a:|mx:|ptr:)([a-zA-Z0-9._-]+)")
SRV_PREFIXES = [
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_sipfederationtls._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_autodiscover._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
    "_imap._tcp",
    "_imaps._tcp",
    "_submission._tcp",
    "_pop3._tcp",
    "_pop3s._tcp",
    "_vlmcs._tcp",
    "_minecraft._tcp",
    "_dmarc",
]
TXT_HOST_PREFIXES = [
    "",
    "_dmarc",
    "_domainkey",
    "default._domainkey",
    "selector1._domainkey",
    "selector2._domainkey",
]


def _pool(ctx: RunContext) -> ResolverPool:
    from allfinder.core.dns.massresolve import get_pool

    return get_pool(ctx)


class AxfrNsec(Plugin):
    name = "axfr"
    kind = SourceKind.ACTIVE
    description = "zone transfer (AXFR) on every NS, then NSEC/NSEC3 walk"
    default_timeout = 120
    weight = 6
    recursive = True
    tags = ("active", "dns", "records")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        pool = _pool(ctx)
        ns_hosts = await pool.records(target.root, "NS")
        ns_hosts = [n.rstrip(".") for n in ns_hosts] or []
        ns_ips: list[str] = []
        for ns in ns_hosts:
            res = await pool.resolve(ns)
            ns_ips.extend(res.a)
        emitted = False
        for ip in dict.fromkeys(ns_ips):
            try:
                async for host in self._axfr(target.root, ip):
                    f = self.finding(host)
                    if f:
                        emitted = True
                        yield f
            except Exception as exc:  # AXFR is refused by most servers
                ctx.log.debug("AXFR %s via %s failed: %s", target.root, ip, exc)
        if not emitted:
            async for host in self._nsec_walk(ctx, target.root):
                f = self.finding(host)
                if f:
                    yield f

    async def _axfr(self, zone_name: str, ip: str) -> AsyncIterator[str]:
        name = dns.name.from_text(zone_name)
        zone = dns.zone.Zone(name)
        try:
            await asyncio.wait_for(self._do_xfr(zone, name, ip), timeout=30)
        except TimeoutError:
            return
        for dnsname, node in zone.nodes.items():
            label = dnsname.to_text()
            if label in (".", "@"):
                yield zone_name
            else:
                yield f"{label.rstrip('.')}.{zone_name}"
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    target = getattr(rdata, "target", None) or getattr(rdata, "mname", None)
                    if target is not None:
                        yield target.to_text().rstrip(".")

    async def _do_xfr(self, zone: dns.zone.Zone, name: dns.name.Name, ip: str) -> None:
        query = dns.message.make_query(name, dns.rdatatype.AXFR)
        await dns.asyncquery.inbound_xfr(ip, zone, query, timeout=10, lifetime=25)

    async def _nsec_walk(self, ctx: RunContext, zone: str) -> AsyncIterator[str]:
        """Walk an unsigned-reply NSEC chain (works only on NSEC, not NSEC3)."""
        resolver = dns.asyncresolver.Resolver()
        pool = _pool(ctx)
        resolver.nameservers = [
            ip
            for ns in await pool.records(zone, "NS")
            for ip in (await pool.resolve(ns.rstrip("."))).a
        ][:4]
        if not resolver.nameservers:
            return
        current = zone
        seen: set[str] = set()
        for _ in range(5000):
            try:
                answer = await asyncio.wait_for(
                    resolver.resolve(current, "NSEC", raise_on_no_answer=False), timeout=5
                )
            except Exception:
                return
            nxt = None
            rrsets = list(answer.response.answer) + list(answer.response.authority)
            for rrset in rrsets:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    for rd in rrset:
                        nxt = rd.next.to_text().rstrip(".")
            if not nxt or nxt in seen or not (nxt == zone or nxt.endswith("." + zone)):
                return
            seen.add(nxt)
            yield nxt
            current = nxt


class RecordMiner(Plugin):
    name = "records"
    kind = SourceKind.ACTIVE
    description = "mine SOA/NS/MX/TXT/SPF/SRV records and CNAME chains for hostnames"
    default_timeout = 180
    weight = 5
    recursive = True
    tags = ("active", "dns", "records")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        pool = _pool(ctx)
        seen: set[str] = set()

        async def emit(raw: str | None) -> Finding | None:
            f = self.finding(raw)
            if f and f.hostname not in seen:
                seen.add(f.hostname)
                return f
            return None

        # NS / MX / SOA on the apex
        for qt in ("NS", "MX", "SOA"):
            for data in await pool.records(target.root, qt):
                host = data.split()[-1] if qt == "MX" else data.split()[0]
                r = await emit(host)
                if r:
                    yield r

        # SPF / DMARC / DKIM TXT on the apex and common selectors
        for prefix in TXT_HOST_PREFIXES:
            name = f"{prefix}.{target.root}" if prefix else target.root
            for txt in await pool.records(name, "TXT"):
                for m in _SPF_INCLUDE.finditer(txt):
                    r = await emit(m.group(1))
                    if r:
                        yield r

        # SRV service records
        srv_names = [f"{p}.{target.root}" for p in SRV_PREFIXES]
        srv_results = await asyncio.gather(
            *(pool.records(n, "SRV") for n in srv_names), return_exceptions=True
        )
        for result in srv_results:
            if isinstance(result, list):
                for data in result:
                    r = await emit(data.split()[-1])
                    if r:
                        yield r

        # follow CNAME chains of already-known resolved names
        for sub in ctx.store.subdomains([target.apex], resolved=True):
            if sub.cname:
                r = await emit(sub.cname)
                if r:
                    yield r
