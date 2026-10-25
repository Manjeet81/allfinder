"""SiteDossier parent-domain listing (HTML, free, paginated by 100)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

URL = "http://www.sitedossier.com/parentdomain/{domain}/{offset}"
MAX_PAGES = 20


class SiteDossier(HttpPlugin):
    name = "sitedossier"
    kind = SourceKind.PASSIVE
    description = "sitedossier.com parent domain pages"
    rate_limit = 0.5
    weight = 3
    tags = ("free", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(MAX_PAGES):
            offset = page * 100 + 1
            html = await self.get_text(
                ctx, URL.format(domain=target.root, offset=offset), ok=[404, 302]
            )
            if not html or "no data currently available" in html.lower():
                break
            new = 0
            for f in self.findings_from_text(html, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    new += 1
                    yield f
            if new == 0 or "show next" not in html.lower():
                break
