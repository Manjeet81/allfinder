"""Common Crawl URL index (free).  Queries the newest few indices."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

COLLINFO = "https://index.commoncrawl.org/collinfo.json"
INDICES = 3
MAX_LINES = 500_000


class CommonCrawl(HttpPlugin):
    name = "commoncrawl"
    kind = SourceKind.PASSIVE
    description = "Common Crawl index (archived URLs)"
    default_timeout = 300
    rate_limit = 1.0
    weight = 4
    tags = ("free", "archives")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        info = await self.get_json(ctx, COLLINFO)
        if not isinstance(info, list):
            return
        apis = [i.get("cdx-api") for i in info if isinstance(i, dict) and i.get("cdx-api")]
        seen: set[str] = set()
        for api in [str(a) for a in apis[:INDICES]]:
            params = {"url": f"*.{target.root}", "output": "json", "fl": "url"}
            try:
                async for line in self.stream_lines(
                    ctx, api, params=params, max_lines=MAX_LINES, ok=[404]
                ):
                    url = line
                    if line.startswith("{"):
                        try:
                            url = json.loads(line).get("url", "")
                        except ValueError:
                            continue
                    for f in self.findings_from_values([url], target):
                        if f.hostname not in seen:
                            seen.add(f.hostname)
                            yield f
            except Exception as exc:  # one broken index must not kill the others
                self.log.debug("commoncrawl index %s failed: %s", api, exc)
                if not seen and api == apis[min(INDICES, len(apis)) - 1]:
                    raise
