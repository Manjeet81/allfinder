"""Tag resolved hosts with ASN / org / CDN using the free ip-api.com batch API."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

BATCH_API = "http://ip-api.com/batch"
BATCH_SIZE = 100
FIELDS = "status,query,as,asname,org,isp"


class IpInfo(HttpPlugin):
    name = "ipinfo"
    kind = SourceKind.ENRICH
    description = "ASN/org tagging of resolved IPs (ip-api.com)"
    default_timeout = 300
    rate_limit = 0.5  # 45 req/min free
    weight = 2
    needs_resolved = True
    tags = ("enrich", "asn")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        ip_to_hosts: dict[str, list[str]] = {}
        for sub in ctx.store.subdomains([target.apex], resolved=True):
            for ip in sub.ips:
                if ":" not in ip:
                    ip_to_hosts.setdefault(ip, []).append(sub.hostname)
        ips = list(ip_to_hosts)
        if not ips:
            return
        for i in range(0, len(ips), BATCH_SIZE):
            if ctx.cancelled:
                break
            batch = ips[i : i + BATCH_SIZE]
            payload = [{"query": ip, "fields": FIELDS} for ip in batch]
            data = await self.request(ctx, "POST", BATCH_API, json=payload, ok=[429])
            if data.status_code == 429:
                return
            try:
                rows = data.json()
            except ValueError:
                return
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict) or row.get("status") != "success":
                    continue
                qip = row.get("query")
                if not isinstance(qip, str):
                    continue
                asn = str(row.get("as") or row.get("asname") or "") or None
                org = str(row.get("org") or row.get("isp") or "") or None
                for host in ip_to_hosts.get(qip, []):
                    ctx.store.update_asn(host, asn, org)
            # one representative finding is not needed; enrichment updates in place
        return
        yield  # pragma: no cover - makes this an async generator
