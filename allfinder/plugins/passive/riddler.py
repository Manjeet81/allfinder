"""Riddler.io (F-Secure) CSV export.  Often requires login; degrades gracefully."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin, SkipPlugin

API = "https://riddler.io/search/exportcsv"


class Riddler(HttpPlugin):
    name = "riddler"
    kind = SourceKind.PASSIVE
    description = "riddler.io search export"
    rate_limit = 1.0
    weight = 2
    tags = ("free", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        resp = await self.get(ctx, API, params={"q": f"pld:{target.root}"}, ok=[401, 403, 404])
        if resp.status_code in (401, 403):
            raise SkipPlugin("riddler requires a login session")
        if resp.status_code == 404:
            return
        for f in self.findings_from_text(resp.text, target):
            yield f
