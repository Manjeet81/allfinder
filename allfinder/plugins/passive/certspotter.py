"""Cert Spotter (SSLMate) certificate transparency API.  Free; a key raises limits."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.certspotter.com/v1/issuances"
MAX_PAGES = 50


class CertSpotter(HttpPlugin):
    name = "certspotter"
    kind = SourceKind.PASSIVE
    description = "Cert Spotter CT issuances (free; key optional)"
    key_provider = "certspotter"
    rate_limit = 1.0
    recursive = True
    weight = 8
    tags = ("free", "ct", "quick")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        key = self.key(ctx)
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        after: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            params = {
                "domain": target.root,
                "include_subdomains": "true",
                "expand": "dns_names",
            }
            if after:
                params["after"] = after
            data = await self.get_json(ctx, API, params=params, headers=headers, key=key)
            if not isinstance(data, list) or not data:
                break
            values: list[str] = []
            for cert in data:
                if isinstance(cert, dict):
                    values.extend(n for n in cert.get("dns_names", []) if isinstance(n, str))
            for f in self.findings_from_values(values, target, in_scope_only=False):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
            last = data[-1]
            after = str(last.get("id")) if isinstance(last, dict) and last.get("id") else None
            if not after:
                break
