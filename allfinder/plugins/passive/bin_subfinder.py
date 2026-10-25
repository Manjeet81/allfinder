"""projectdiscovery subfinder (aggregates dozens of sources itself)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class Subfinder(LineBinaryPlugin):
    name = "subfinder"
    kind = SourceKind.PASSIVE
    description = "projectdiscovery subfinder -all (binary)"
    binary = "subfinder"
    default_timeout = 900
    weight = 9
    recursive = True
    tags = ("binaries", "aggregator", "free")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        args = ["-d", target.root, "-all", "-silent", "-json", "-timeout", "30"]
        provider_cfg = provider_config_path(ctx)
        if provider_cfg is not None:
            args += ["-pc", str(provider_cfg)]
        return args

    def parse_line(self, line: str, target: Target) -> list[Finding]:
        line = line.strip()
        if not line:
            return []
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                return []
            host = obj.get("host") or obj.get("hostname")
            src = obj.get("source")
            f = self.finding(host, extra={"via": src} if src else None)
            if f is None:
                return []
            ip = obj.get("ip")
            if isinstance(ip, str) and ip:
                f.ips.append(ip)
            return [f]
        f = self.finding(line.split()[0])
        return [f] if f else []


def provider_config_path(ctx: RunContext) -> Path | None:
    """Generate a subfinder provider-config.yaml from our key ring (if any keys)."""
    if ctx.config.subfinder_provider_config != "auto":
        p = Path(ctx.config.subfinder_provider_config)
        return p if p.is_file() else None
    try:
        from allfinder.core.providers import write_subfinder_provider_config
    except ImportError:
        return None
    return write_subfinder_provider_config(ctx)
