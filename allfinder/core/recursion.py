"""Feedback loops and sub-root recursion (pipeline stage 4).

After resolution, any resolved name that is itself a parent of other names
(e.g. ``api.example.com`` when ``v1.api.example.com`` exists) or has several
siblings becomes a sub-root; a cheap passive set + permutation runs on it,
depth-limited and time-bounded, feeding results back into resolution.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING

from allfinder.core.models import SourceKind, Target
from allfinder.core.normalize import depth_below, in_scope
from allfinder.core.runner import run_plugins_multi

if TYPE_CHECKING:
    from allfinder.core.pipeline import Pipeline

log = logging.getLogger("allfinder.recursion")


def sub_roots(pipeline: Pipeline, root: str, *, done: set[str]) -> list[str]:
    """Pick promising sub-roots under *root* from the current store contents."""
    ctx = pipeline.ctx
    min_children = ctx.options.recursion_min_children
    parent_counts: Counter[str] = Counter()
    resolved_parents: set[str] = set()
    for sub in ctx.store.subdomains([root]):
        host = sub.hostname
        if not in_scope(host, root) or host == root:
            continue
        if depth_below(host, root) >= 2:
            parent = host.split(".", 1)[1]
            parent_counts[parent] += 1
        if sub.resolved and depth_below(host, root) >= 1:
            resolved_parents.add(host)
    candidates: set[str] = set()
    for parent, n in parent_counts.items():
        if n >= min_children and parent not in done:
            candidates.add(parent)
    for host in resolved_parents:
        if parent_counts.get(host, 0) >= 1 and host not in done:
            candidates.add(host)
    # never recurse on the root itself; keep only in-scope sub-roots
    return sorted(c for c in candidates if c != root and in_scope(c, root))


async def recursion_rounds(pipeline: Pipeline) -> None:
    ctx = pipeline.ctx
    opts = ctx.options
    if opts.depth <= 0:
        return
    registry = pipeline.registry
    # cheap, fast passive sources + permutation, marked recursive=True
    recursive_passive = [p for p in pipeline.select(SourceKind.PASSIVE) if p.recursive]
    permute = (
        [p for p in registry.select(use=["permutation"]) if opts.permute]
        if registry.has("permutation")
        else []
    )
    done: set[str] = set()

    for depth in range(1, opts.depth + 1):
        if ctx.cancelled or ctx.out_of_time():
            break
        before = len(ctx.store)
        targets: list[Target] = []
        for root in ctx.scope.roots:
            for sr in sub_roots(pipeline, root, done=done):
                done.add(sr)
                targets.append(Target(root=sr, roots=ctx.scope.roots, depth=depth, parent=root))
        if not targets:
            log.debug("recursion depth %d: no new sub-roots", depth)
            break
        ctx.notice(f"recursion depth {depth}: {len(targets)} sub-roots", "info")
        plugins = [*recursive_passive, *permute]
        await run_plugins_multi(plugins, ctx, targets)
        await pipeline.stage_resolve()
        if opts.active and not opts.passive_only:
            active = [p for p in pipeline.select(SourceKind.ACTIVE) if p.recursive]
            if active:
                await run_plugins_multi(active, ctx, targets)
                await pipeline.stage_resolve()
        gained = len(ctx.store) - before
        ctx.log.info("recursion depth %d: +%d names", depth, gained)
        if gained == 0:
            break
