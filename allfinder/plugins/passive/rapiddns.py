"""RapidDNS (HTML scrape, free)."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

URL = "https://rapiddns.io/subdomain/{domain}"
MAX_PAGES = 30
_TOTAL_RE = re.compile(r"Total:\s*<span[^>]*>\s*([\d,]+)", re.IGNORECASE)
_PAGE_RE = re.compile(r"[?&]page=(\d+)")


class RapidDns(HttpPlugin):
    name = "rapiddns"
    kind = SourceKind.PASSIVE
    description = "rapiddns.io subdomain pages"
    rate_limit = 1.0
    recursive = True
    weight = 6
    tags = ("free", "dns", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        last_page = 1
        for page in range(1, MAX_PAGES + 1):
            html = await self.get_text(
                ctx,
                URL.format(domain=target.root),
                params={"full": 1, "down": 1, "page": page},
                ok=[404],
            )
            if not html:
                break
            new = 0
            for f in self.findings_from_text(html, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    new += 1
                    yield f
            if page == 1:
                pages = [int(p) for p in _PAGE_RE.findall(html)]
                last_page = max(pages) if pages else 1
            if page >= last_page or new == 0:
                break
