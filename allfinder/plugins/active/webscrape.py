"""Scrape live hosts for more in-scope names: headers, robots/sitemap/security.txt,
HTML links and linked JS files (shallow)."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.http import HttpError
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

WELL_KNOWN = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/humans.txt",
]
HEADER_KEYS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "access-control-allow-origin",
    "link",
    "x-pingback",
    "report-to",
    "location",
]
_SRC_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)""", re.IGNORECASE)
_JS_RE = re.compile(r"""["']([^"']+?\.js)(?:["'?])""", re.IGNORECASE)
MAX_HOSTS = 500
MAX_JS = 40


class WebScrape(HttpPlugin):
    name = "webscrape"
    kind = SourceKind.ACTIVE
    description = "scrape live hosts (CSP, robots/sitemap, HTML + JS) for in-scope names"
    default_timeout = 600
    rate_limit = None
    weight = 3
    needs_resolved = True
    tags = ("active", "web")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        hosts = [
            s.hostname
            for s in ctx.store.subdomains([target.apex], resolved=True)
            if (s.hostname == target.root or s.hostname.endswith("." + target.root))
        ][:MAX_HOSTS]
        seen: set[str] = set()
        for host in hosts:
            if ctx.cancelled or ctx.out_of_time():
                break
            async for f in self._scrape_host(ctx, host, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f

    async def _scrape_host(
        self, ctx: RunContext, host: str, target: Target
    ) -> AsyncIterator[Finding]:
        base = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                resp = await self.get(ctx, url, ok=list(range(200, 500)))
            except HttpError:
                continue
            base = scheme
            # headers
            header_blob = " ".join(
                f"{k}: {resp.headers[k]}" for k in HEADER_KEYS if k in resp.headers
            )
            for f in self.findings_from_text(header_blob, target):
                yield f
            # body links + inline hostnames
            body = resp.text
            for f in self.findings_from_text(body, target):
                yield f
            js_urls = self._js_links(body, host, scheme)
            for js in js_urls[:MAX_JS]:
                try:
                    jtext = await self.get_text(ctx, js, ok=list(range(200, 500)))
                except HttpError:
                    continue
                for f in self.findings_from_text(jtext, target):
                    yield f
            break
        if base is None:
            return
        # well-known files
        for path in WELL_KNOWN:
            try:
                text = await self.get_text(ctx, f"{base}://{host}{path}", ok=list(range(200, 500)))
            except HttpError:
                continue
            for f in self.findings_from_text(text, target):
                yield f

    def _js_links(self, html: str, host: str, scheme: str) -> list[str]:
        urls: list[str] = []
        for m in list(_SRC_RE.finditer(html)) + list(_JS_RE.finditer(html)):
            ref = m.group(1)
            if not ref.endswith(".js") and ".js?" not in ref:
                continue
            if ref.startswith("http"):
                urls.append(ref)
            elif ref.startswith("//"):
                urls.append(f"{scheme}:{ref}")
            elif ref.startswith("/"):
                urls.append(f"{scheme}://{host}{ref}")
            else:
                urls.append(f"{scheme}://{host}/{ref}")
        return list(dict.fromkeys(urls))
