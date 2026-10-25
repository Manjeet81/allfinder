"""SecurityTrails subdomains endpoint (key required)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

API = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"


class SecurityTrails(HttpPlugin):
    name = "securitytrails"
    kind = SourceKind.PASSIVE
    description = "SecurityTrails domain subdomains"
    key_provider = "securitytrails"
    requires = {"api_keys": ["securitytrails"]}
    rate_limit = 1.0
    weight = 8
    tags = ("keyed", "dns")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        data = await self.keyed_json(
            ctx,
            API.format(domain=target.root),
            auth=lambda k: {"headers": {"APIKEY": k}},
            params={"children_only": "false", "include_inactive": "true"},
            ok=[404],
        )
        if not isinstance(data, dict):
            return
        values = [f"{p}.{target.root}" for p in data.get("subdomains") or [] if isinstance(p, str)]
        for f in self.findings_from_values(values, target):
            yield f
