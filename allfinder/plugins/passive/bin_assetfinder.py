"""tomnomnom assetfinder (binary)."""

from __future__ import annotations

from collections.abc import Sequence

from allfinder.core.context import RunContext
from allfinder.core.models import SourceKind, Target
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class AssetFinder(LineBinaryPlugin):
    name = "assetfinder"
    kind = SourceKind.PASSIVE
    description = "assetfinder --subs-only (binary)"
    binary = "assetfinder"
    default_timeout = 300
    weight = 6
    recursive = True
    tags = ("binaries", "aggregator", "free")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return ["--subs-only", target.root]
