"""Reverse DNS (PTR) over the /24 of every resolved in-scope IP."""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import Plugin

MAX_IPS = 4096


class ReverseDns(Plugin):
    name = "reverse-dns"
    kind = SourceKind.ACTIVE
    description = "PTR lookups across the /24 of every resolved IP"
    default_timeout = 600
    weight = 3
    needs_resolved = True
    tags = ("active", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        from allfinder.core.dns.massresolve import get_pool

        pool = get_pool(ctx)
        networks: set[ipaddress.IPv4Network] = set()
        for sub in ctx.store.subdomains([target.apex], resolved=True):
            for ip in sub.ips:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if isinstance(addr, ipaddress.IPv4Address) and not addr.is_private:
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                    assert isinstance(net, ipaddress.IPv4Network)
                    networks.add(net)
        addrs: list[str] = []
        for net in networks:
            addrs.extend(str(h) for h in net.hosts())
            if len(addrs) >= MAX_IPS:
                break
        addrs = addrs[:MAX_IPS]
        if not addrs:
            return
        ctx.log.info("reverse DNS: %d addresses in %d /24s", len(addrs), len(networks))
        seen: set[str] = set()
        for ip in addrs:
            if ctx.cancelled or ctx.out_of_time():
                break
            rev = ipaddress.ip_address(ip).reverse_pointer
            for ptr in await pool.records(rev, "PTR"):
                f = self.finding(ptr.rstrip("."), ips=[ip])
                # a /24 hosts unrelated domains; keep only in-scope PTR names
                if f and f.hostname not in seen and (
                    f.hostname == target.root or f.hostname.endswith("." + target.root)
                ):
                    seen.add(f.hostname)
                    yield f
