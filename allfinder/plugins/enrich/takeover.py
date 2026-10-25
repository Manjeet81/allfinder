"""Subdomain takeover detection via CNAME fingerprints (can-i-take-over-xyz)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.http import HttpError
from allfinder.core.models import Finding, SourceKind, Subdomain, Target
from allfinder.core.wordlists import locate
from allfinder.plugins.base import HttpPlugin

# minimal built-in set so takeover works with no data download
BUILTIN_FINGERPRINTS: list[dict[str, object]] = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io", "github.map.fastly.net"],
        "fingerprint": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
    },
    {
        "service": "AWS/S3",
        "cname": ["amazonaws.com"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    {
        "service": "Heroku",
        "cname": ["herokuapp.com", "herokudns.com"],
        "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    },
    {"service": "Fastly", "cname": ["fastly.net"], "fingerprint": ["Fastly error: unknown domain"]},
    {
        "service": "Shopify",
        "cname": ["myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable"],
    },
    {"service": "Surge.sh", "cname": ["surge.sh"], "fingerprint": ["project not found"]},
    {
        "service": "Tumblr",
        "cname": ["domains.tumblr.com"],
        "fingerprint": ["Whatever you were looking for doesn't currently exist at this address"],
    },
    {
        "service": "Unbounce",
        "cname": ["unbouncepages.com"],
        "fingerprint": ["The requested URL was not found on this server"],
    },
    {
        "service": "Pantheon",
        "cname": ["pantheonsite.io"],
        "fingerprint": ["The gods are wise, but do not know of the site which you seek"],
    },
    {"service": "Zendesk", "cname": ["zendesk.com"], "fingerprint": ["Help Center Closed"]},
    {
        "service": "Ghost",
        "cname": ["ghost.io"],
        "fingerprint": ["The thing you were looking for is no longer here, or never was"],
    },
    {
        "service": "Readme.io",
        "cname": ["readme.io"],
        "fingerprint": ["Project doesnt exist... yet!"],
    },
]


def _as_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return []


def load_fingerprints(ctx: RunContext) -> list[dict[str, object]]:
    path = locate(ctx.config, "takeover-fingerprints")
    if path is not None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            data = None
        if isinstance(data, list):
            out: list[dict[str, object]] = []
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                cnames = entry.get("cname") or []
                fps = entry.get("fingerprint") or []
                fps = [fps] if isinstance(fps, str) else fps
                if cnames and entry.get("status", "").lower() not in ("not vulnerable",):
                    out.append(
                        {
                            "service": entry.get("service", "?"),
                            "cname": cnames,
                            "fingerprint": [f for f in fps if f],
                        }
                    )
            if out:
                return out
    return BUILTIN_FINGERPRINTS


class Takeover(HttpPlugin):
    name = "takeover"
    kind = SourceKind.ENRICH
    description = "subdomain takeover check (CNAME fingerprints)"
    default_timeout = 600
    rate_limit = None
    weight = 5
    needs_resolved = True
    tags = ("enrich", "takeover")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        import asyncio

        fingerprints = load_fingerprints(ctx)
        subs = [
            s
            for s in ctx.store.subdomains([target.apex])
            if s.cname and (s.hostname == target.root or s.hostname.endswith("." + target.root))
        ]
        sem = asyncio.Semaphore(min(30, max(5, ctx.options.concurrency)))

        async def check(sub: Subdomain) -> Finding | None:
            cname = (sub.cname or "").lower()
            matches = [fp for fp in fingerprints if any(c in cname for c in _as_list(fp["cname"]))]
            if not matches:
                return None
            service = str(matches[0]["service"])
            vulnerable = False
            evidence = None
            async with sem:
                for scheme in ("https", "http"):
                    try:
                        resp = await self.get(
                            ctx, f"{scheme}://{sub.hostname}/", ok=list(range(200, 600))
                        )
                    except HttpError:
                        continue
                    body = resp.text
                    for fp in matches:
                        for marker in _as_list(fp["fingerprint"]):
                            if marker and marker in body:
                                vulnerable = True
                                service = str(fp["service"])
                                evidence = marker[:80]
                                break
                        if vulnerable:
                            break
                    break
            data = {
                "service": service,
                "cname": sub.cname,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "dangling": not sub.resolved,
            }
            ctx.store.update_takeover(sub.hostname, data)
            if vulnerable or not sub.resolved:
                ctx.notice(
                    f"[takeover] {sub.hostname} -> {sub.cname} ({service}) "
                    f"{'VULNERABLE' if vulnerable else 'dangling CNAME'}",
                    "warning",
                )
                return Finding(sub.hostname, self.name, cname=sub.cname, extra=data)
            return None

        results = await asyncio.gather(*(check(s) for s in subs))
        for f in results:
            if f is not None:
                yield f
