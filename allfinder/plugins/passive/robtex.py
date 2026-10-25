"""Robtex free passive-DNS API: forward records, then reverse on the IPs."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

FORWARD = "https://freeapi.robtex.com/pdns/forward/{domain}"
REVERSE = "https://freeapi.robtex.com/pdns/reverse/{ip}"
MAX_IPS = 20


def _records(text: str) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


class Robtex(HttpPlugin):
    name = "robtex"
    kind = SourceKind.PASSIVE
    description = "Robtex passive DNS (forward + reverse)"
    rate_limit = 0.5
    weight = 3
    tags = ("free", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        text = await self.get_text(ctx, FORWARD.format(domain=target.root), ok=[404])
        seen: set[str] = set()
        ips: list[str] = []
        for rec in _records(text):
            rtype = str(rec.get("rrtype") or "").upper()
            rdata = str(rec.get("rrdata") or "")
            if rtype in ("A", "AAAA") and rdata and rdata not in ips:
                ips.append(rdata)
            f = self.finding(str(rec.get("rrname") or ""))
            if f and f.hostname not in seen:
                seen.add(f.hostname)
                yield f
        for ip in ips[:MAX_IPS]:
            text = await self.get_text(ctx, REVERSE.format(ip=ip), ok=[404])
            for rec in _records(text):
                f = self.finding(str(rec.get("rrname") or ""), ips=[ip])
                if f and f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
