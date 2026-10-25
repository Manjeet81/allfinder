"""OWASP amass passive enumeration (binary).  Parses any v3/v4/v5 stdout."""

from __future__ import annotations

from collections.abc import Sequence

from allfinder.core.context import RunContext
from allfinder.core.models import SourceKind, Target
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class Amass(LineBinaryPlugin):
    name = "amass"
    kind = SourceKind.PASSIVE
    description = "OWASP amass enum -passive (binary)"
    binary = "amass"
    default_timeout = 1200
    weight = 2  # slow: start it early but it rarely finishes first
    extract = True  # v4 prints "name (FQDN) --> a_record --> ip (IPAddress)"
    tags = ("binaries", "aggregator", "free", "slow")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        minutes = max(1, int(ctx.timeout_for(self.name, self.default_timeout) // 60))
        return [
            "enum",
            "-passive",
            "-d",
            target.root,
            "-nocolor",
            "-silent",
            "-timeout",
            str(minutes),
        ]
