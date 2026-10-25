"""Permutation / alteration engine (native) + alterx/gotator/dnsgen wrappers.

Runs on already-resolved names (quality over quantity): tokenises known
hostnames, applies prefix/suffix/number/region patterns, resolves the
candidates and keeps the ones that answer (and are not wildcard-only).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterable, Sequence

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import Plugin
from allfinder.plugins.passive.bin_common import LineBinaryPlugin

WORDS = [
    "dev",
    "development",
    "test",
    "testing",
    "stage",
    "staging",
    "stg",
    "prod",
    "production",
    "preprod",
    "uat",
    "qa",
    "demo",
    "sandbox",
    "beta",
    "alpha",
    "canary",
    "preview",
    "new",
    "old",
    "api",
    "api2",
    "internal",
    "int",
    "external",
    "ext",
    "admin",
    "portal",
    "app",
    "apps",
    "web",
    "mobile",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "secure",
    "vpn",
    "proxy",
    "gateway",
    "gw",
    "edge",
    "origin",
    "backup",
    "db",
    "cache",
    "mail",
    "smtp",
    "ns",
    "auth",
    "sso",
    "login",
    "us",
    "eu",
    "asia",
    "east",
    "west",
    "north",
    "south",
    "central",
    "v1",
    "v2",
    "v3",
    "1",
    "2",
    "01",
    "02",
]
REGIONS = [
    "us",
    "eu",
    "ap",
    "us-east",
    "us-west",
    "eu-west",
    "eu-central",
    "ap-south",
    "us-east-1",
    "us-west-2",
    "eu-west-1",
]
_SPLIT = re.compile(r"[-_.]")
_NUM = re.compile(r"(\d+)")


def tokenize(labels: Iterable[str]) -> set[str]:
    """Words learned from known labels (split on -, _, and digit boundaries)."""
    words: set[str] = set()
    for label in labels:
        for piece in _SPLIT.split(label):
            if piece:
                words.add(piece)
                for sub in _NUM.split(piece):
                    if sub:
                        words.add(sub)
    return words


def permute_label(label: str, words: Sequence[str]) -> set[str]:
    """Variations of one leftmost label."""
    out: set[str] = set()
    for w in words:
        out.add(f"{w}-{label}")
        out.add(f"{label}-{w}")
        out.add(f"{w}.{label}")
        out.add(f"{w}{label}")
        out.add(f"{label}{w}")
    # number increment/decrement and zero-padding on trailing digits
    m = re.search(r"(\d+)$", label)
    if m:
        num = int(m.group(1))
        stem = label[: m.start(1)]
        width = len(m.group(1))
        for n in {num + 1, num + 2, max(0, num - 1), 0, 1, 2}:
            out.add(f"{stem}{n}")
            out.add(f"{stem}{n:0{width}d}")
    else:
        for n in (1, 2, 0):
            out.add(f"{label}{n}")
    out.discard(label)
    return out


def generate(
    hostnames: Iterable[str],
    roots: Iterable[str],
    *,
    extra_words: Iterable[str] = (),
    max_results: int = 200_000,
) -> set[str]:
    """Build a bounded candidate set from resolved *hostnames*."""
    roots = list(roots)
    words = sorted(
        set(WORDS) | set(REGIONS) | tokenize(_all_labels(hostnames, roots)) | set(extra_words)
    )
    out: set[str] = set()
    for host in hostnames:
        root = _root_of(host, roots)
        if root is None or host == root:
            continue
        suffix = host[: -(len(root) + 1)]
        labels = suffix.split(".")
        head, rest = labels[0], labels[1:]
        tail = (".".join(rest) + "." if rest else "") + root
        for variant in permute_label(head, words):
            out.add(f"{variant}.{tail}")
            if len(out) >= max_results:
                return out
        # add a word as a brand-new leftmost label too
        for w in words:
            out.add(f"{w}.{suffix}.{root}")
            if len(out) >= max_results:
                return out
    return out


def _all_labels(hostnames: Iterable[str], roots: list[str]) -> set[str]:
    labels: set[str] = set()
    for host in hostnames:
        root = _root_of(host, roots)
        if root and host != root:
            labels.update(host[: -(len(root) + 1)].split("."))
    return labels


def _root_of(host: str, roots: list[str]) -> str | None:
    for r in sorted(roots, key=len, reverse=True):
        if host == r or host.endswith("." + r):
            return r
    return None


class Permutation(Plugin):
    name = "permutation"
    kind = SourceKind.ACTIVE
    description = "native permutation engine on resolved names, then resolve"
    weight = 4
    needs_resolved = True
    tags = ("active", "permute")

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        if not ctx.options.permute:
            return
        from allfinder.core.dns.massresolve import attempted, resolve_hosts

        resolved = [
            s.hostname
            for s in ctx.store.subdomains([target.apex], resolved=True)
            if s.hostname.endswith("." + target.root) or s.hostname == target.root
        ]
        if not resolved:
            return
        candidates = generate(resolved, [target.root], max_results=ctx.options.max_permutations)
        done = attempted(ctx)
        candidates = {c for c in candidates if c not in done and c not in ctx.store}
        if not candidates:
            return
        ctx.log.info("permutation: %d candidates under %s", len(candidates), target.root)
        results = await resolve_hosts(ctx, candidates, root=target.root, validate_hits=True)
        for host, res in results.items():
            if res.resolved and not res.wildcard:
                yield Finding(
                    host, self.name, ips=res.ips, cname=res.cname[0] if res.cname else None
                )


class AlterX(LineBinaryPlugin):
    name = "alterx"
    kind = SourceKind.ACTIVE
    description = "projectdiscovery alterx permutations (binary) -> resolve"
    binary = "alterx"
    weight = 3
    needs_resolved = True
    tags = ("active", "permute", "binaries")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        return ["-enrich", "-silent"]

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        from allfinder.core.dns.massresolve import resolve_hosts

        resolved = [
            s.hostname
            for s in ctx.store.subdomains([target.apex], resolved=True)
            if s.hostname.endswith("." + target.root) or s.hostname == target.root
        ]
        if not resolved:
            return
        candidates: set[str] = set()
        stdin = "\n".join(resolved) + "\n"
        async for line in self.lines(ctx, self.args(ctx, target), stdin_data=stdin, check=False):
            for f in self.parse_line(line, target):
                candidates.add(f.hostname)
                if len(candidates) >= ctx.options.max_permutations:
                    break
        candidates = {c for c in candidates if c not in ctx.store}
        if not candidates:
            return
        results = await resolve_hosts(ctx, candidates, root=target.root, validate_hits=True)
        for host, res in results.items():
            if res.resolved and not res.wildcard:
                yield Finding(
                    host, self.name, ips=res.ips, cname=res.cname[0] if res.cname else None
                )
