"""Findomain (binary)."""

from __future__ import annotations

from collections.abc import Sequence

from allfinder.core.context import RunContext
from allfinder.core.models import SourceKind, Target
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class Findomain(LineBinaryPlugin):
    name = "findomain"
    kind = SourceKind.PASSIVE
    description = "findomain -q (binary)"
    binary = "findomain"
    default_timeout = 600
    weight = 6
    tags = ("binaries", "aggregator", "free")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return ["-q", "-t", target.root]
