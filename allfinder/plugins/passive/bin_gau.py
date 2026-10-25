"""gau (getallurls) and waybackurls: archived URLs -> hostnames (binaries)."""

from __future__ import annotations

from collections.abc import Sequence

from allfinder.core.context import RunContext
from allfinder.core.models import SourceKind, Target
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class Gau(LineBinaryPlugin):
    name = "gau"
    kind = SourceKind.PASSIVE
    description = "gau --subs (wayback+commoncrawl+otx+urlscan URLs, binary)"
    binary = "gau"
    default_timeout = 900
    weight = 4
    extract = True
    tags = ("binaries", "archives", "free")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return ["--subs", "--threads", "5", target.root]


class WaybackUrls(LineBinaryPlugin):
    name = "waybackurls"
    kind = SourceKind.PASSIVE
    description = "waybackurls (binary)"
    binary = "waybackurls"
    default_timeout = 900
    weight = 3
    extract = True
    stdin_target = True
    tags = ("binaries", "archives", "free")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return []
