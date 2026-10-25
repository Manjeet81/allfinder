"""cero: connect to hosts and harvest TLS certificate SANs (binary, active)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class Cero(LineBinaryPlugin):
    name = "cero"
    kind = SourceKind.ACTIVE
    description = "cero TLS SAN harvesting on root + resolved hosts (binary)"
    binary = "cero"
    default_timeout = 600
    weight = 5
    needs_resolved = True
    tags = ("binaries", "ct", "free")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return ["-c", "50", "-p", "443,8443"]

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        hosts = [target.root]
        for sub in ctx.store.subdomains([target.apex], resolved=True):
            if sub.hostname != target.root and sub.hostname.endswith("." + target.root):
                hosts.append(sub.hostname)
        for sub in ctx.store.subdomains([target.apex], resolved=True):
            hosts.extend(ip for ip in sub.ips if ":" not in ip)
        hosts = list(dict.fromkeys(hosts))
        seen: set[str] = set()
        async for line in self.lines(
            ctx, self.args(ctx, target), stdin_data="\n".join(hosts) + "\n", check=False
        ):
            for f in self.parse_line(line, target):
                if f.hostname not in seen:
                    seen.add(f.hostname)
                    yield f
