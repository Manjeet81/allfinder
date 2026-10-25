"""HTTP probe: status, title, tech, server, redirect, IP.  httpx binary or native."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Sequence

from allfinder.core.context import RunContext
from allfinder.core.http import HttpError
from allfinder.core.models import Finding, HttpInfo, SourceKind, Target
from allfinder.plugins.base import BinaryPlugin, HttpPlugin
from allfinder.utils.subprocess import ProcResult

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _probe_targets(ctx: RunContext, target: Target) -> list[str]:
    hosts = []
    for s in ctx.store.subdomains([target.apex]):
        if (s.resolved or ctx.options.keep_wildcards) and (
            s.hostname == target.root or s.hostname.endswith("." + target.root)
        ):
            hosts.append(s.hostname)
    return hosts


class HttpxProbe(BinaryPlugin):
    name = "httpx"
    kind = SourceKind.ENRICH
    description = "httpx probe: status/title/tech/cname/ip (binary)"
    binary = "httpx"
    default_timeout = 1800
    weight = 9
    needs_resolved = True
    tags = ("enrich", "binaries", "http")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return [
            "-json",
            "-silent",
            "-no-color",
            "-title",
            "-status-code",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-location",
            "-cname",
            "-ip",
            "-follow-redirects",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-rate-limit",
            str(max(10, ctx.options.qps // 2)),
        ]

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        hosts = _probe_targets(ctx, target)
        if not hosts:
            return
        res = ProcResult()
        async for line in self.lines(
            ctx, self.args(ctx, target), stdin_data="\n".join(hosts) + "\n", result=res, check=False
        ):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            host = self._host(obj)
            if host is None:
                continue
            info = HttpInfo(
                url=obj.get("url") or f"https://{host}",
                status=obj.get("status_code") or obj.get("status-code"),
                title=obj.get("title"),
                tech=obj.get("tech") or obj.get("technologies") or [],
                content_length=obj.get("content_length") or obj.get("content-length"),
                final_url=obj.get("location") or obj.get("final_url"),
                server=obj.get("webserver") or obj.get("web-server"),
                ip=(obj.get("a") or [None])[0]
                if isinstance(obj.get("a"), list)
                else obj.get("host"),
                cdn=obj.get("cdn_name") or obj.get("cdn"),
            )
            ctx.store.update_http(host, info)
            cname = obj.get("cname")
            if isinstance(cname, list):
                cname = cname[0] if cname else None
            yield Finding(host, self.name, ips=obj.get("a") or [], cname=cname)

    def _host(self, obj: dict[str, object]) -> str | None:
        raw = obj.get("input") or obj.get("host") or obj.get("url")
        f = self.finding(str(raw)) if raw else None
        return f.hostname if f else None


class NativeHttpProbe(HttpPlugin):
    name = "httpx-native"
    kind = SourceKind.ENRICH
    description = "native HTTP probe fallback (status/title/server)"
    default_timeout = 1200
    rate_limit = None
    weight = 1
    needs_resolved = True
    tags = ("enrich", "http")

    def check(self, ctx: RunContext) -> str | None:
        # only runs when the httpx binary is absent (avoids double-probing)
        if ctx.binary("httpx") is not None:
            return "httpx binary present (native probe not needed)"
        return super().check(ctx)

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        import asyncio

        hosts = _probe_targets(ctx, target)
        sem = asyncio.Semaphore(min(50, max(5, ctx.options.concurrency)))

        async def probe(host: str) -> Finding | None:
            async with sem:
                for scheme in ("https", "http"):
                    try:
                        resp = await self.get(ctx, f"{scheme}://{host}/", ok=list(range(200, 600)))
                    except HttpError:
                        continue
                    m = _TITLE_RE.search(resp.text[:65536])
                    info = HttpInfo(
                        url=str(resp.url),
                        status=resp.status_code,
                        title=(m.group(1).strip()[:200] if m else None),
                        server=resp.headers.get("server"),
                        content_length=int(resp.headers["content-length"])
                        if resp.headers.get("content-length", "").isdigit()
                        else None,
                        final_url=str(resp.url),
                    )
                    ctx.store.update_http(host, info)
                    return Finding(host, self.name)
            return None

        results = await asyncio.gather(*(probe(h) for h in hosts))
        for f in results:
            if f is not None:
                yield f
