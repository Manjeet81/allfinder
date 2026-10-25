"""GitHub code search (native, key required) and grep.app (free)."""

from __future__ import annotations

import html
import re
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin
from allfinder.utils.text import iter_strings

GITHUB_SEARCH = "https://api.github.com/search/code"
GREPAPP = "https://grep.app/api/search"
_TAG_RE = re.compile(r"<[^>]+>")


class GithubCode(HttpPlugin):
    name = "github"
    kind = SourceKind.PASSIVE
    description = "GitHub code search text matches (native)"
    key_provider = "github"
    requires = {"api_keys": ["github"]}
    rate_limit = 0.15  # 10 searches/min with a token
    default_timeout = 600
    weight = 3
    tags = ("keyed", "code")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(1, 11):  # API caps at 1000 results
            data = await self.keyed_json(
                ctx,
                GITHUB_SEARCH,
                auth=lambda k: {
                    "headers": {
                        "Authorization": f"token {k}",
                        "Accept": "application/vnd.github.text-match+json",
                    }
                },
                params={"q": f'"{target.root}"', "per_page": 100, "page": page},
                ok=[422],
            )
            if not isinstance(data, dict):
                break
            items = data.get("items") or []
            for item in items:
                for f in self.findings_from_values(list(iter_strings(item)), target):
                    if f.hostname not in seen:
                        seen.add(f.hostname)
                        yield f
            if len(items) < 100:
                break


class GrepApp(HttpPlugin):
    name = "grepapp"
    kind = SourceKind.PASSIVE
    description = "grep.app public code search"
    rate_limit = 1.0
    weight = 3
    tags = ("free", "code")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for page in range(1, 21):
            data = await self.get_json(
                ctx, GREPAPP, params={"q": target.root, "page": page}, ok=[404, 429]
            )
            if not isinstance(data, dict):
                break
            hits = (data.get("hits") or {}).get("hits") or []
            text = html.unescape(_TAG_RE.sub("", " ".join(iter_strings(hits))))
            for f in self.findings_from_text(text, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            if len(hits) < 10:
                break
