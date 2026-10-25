"""Run a set of plugins concurrently with per-plugin timeouts and error capture.

Each finding is stored the moment it arrives.  Errors never abort the run:
they land in ``SourceStats.error`` and are shown at the end.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable
from dataclasses import replace

from allfinder.core.context import RunContext
from allfinder.core.http import HttpError
from allfinder.core.models import Finding, SourceStats, SourceStatus, Target, utcnow
from allfinder.plugins.base import Plugin, SkipPlugin

log = logging.getLogger("allfinder.runner")

_STATUS_RANK = {
    SourceStatus.PENDING: 0,
    SourceStatus.SKIPPED: 1,
    SourceStatus.DONE: 2,
    SourceStatus.RUNNING: 3,
    SourceStatus.TIMEOUT: 4,
    SourceStatus.ERROR: 5,
}


class StatsBook:
    """Aggregates per-source stats across rounds/targets and persists them."""

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx
        self._totals: dict[str, SourceStats] = {}
        self._live: dict[str, SourceStats] = {}

    def begin(self, stats: SourceStats) -> None:
        """Called when a plugin starts (or is skipped) for one target."""
        self._live[stats.source] = stats
        self._emit(stats.source)

    def progress(self, stats: SourceStats) -> None:
        self._emit(stats.source)

    def finish(self, stats: SourceStats) -> None:
        self._live.pop(stats.source, None)
        total = self._totals.get(stats.source)
        if total is None:
            total = replace(stats)
            self._totals[stats.source] = total
        else:
            total.found += stats.found
            total.unique += stats.unique
            total.duration += stats.duration
            if (
                _STATUS_RANK[stats.status] > _STATUS_RANK[total.status]
                or total.status == SourceStatus.SKIPPED
            ):
                total.status = stats.status
            if stats.error:
                total.error = stats.error if not total.error else total.error
            total.finished_at = stats.finished_at
        self.ctx.store.save_stats(total)
        self._emit(stats.source)

    def _merged(self, source: str) -> SourceStats:
        total = self._totals.get(source)
        live = self._live.get(source)
        if total is None and live is None:
            return SourceStats(source)
        if total is None:
            assert live is not None
            return replace(live)
        if live is None:
            return replace(total)
        merged = replace(total)
        merged.found += live.found
        merged.unique += live.unique
        merged.duration += live.duration
        merged.status = live.status
        return merged

    def _emit(self, source: str) -> None:
        if self.ctx.on_stats is not None:
            self.ctx.on_stats(self._merged(source))

    def all(self) -> list[SourceStats]:
        names = set(self._totals) | set(self._live)
        return [self._merged(n) for n in sorted(names)]

    def errors(self) -> list[SourceStats]:
        return [s for s in self.all() if s.status in (SourceStatus.ERROR, SourceStatus.TIMEOUT)]


def get_book(ctx: RunContext) -> StatsBook:
    book = ctx.extras.get("stats_book")
    if book is None:
        book = ctx.extras["stats_book"] = StatsBook(ctx)
    return book


def ingest(ctx: RunContext, finding: Finding, target: Target) -> bool:
    """Store one finding; returns ``True`` if the hostname was new."""
    matched = ctx.scope.root_for(finding.hostname)
    in_scope = matched is not None
    root = matched if matched is not None else target.apex
    is_new = ctx.store.add_finding(finding, root=root, depth=target.depth, in_scope=in_scope)
    if ctx.on_finding is not None and in_scope:
        ctx.on_finding(finding, is_new)
    return is_new


async def run_plugin(
    plugin: Plugin,
    ctx: RunContext,
    target: Target,
    *,
    semaphore: asyncio.Semaphore | None = None,
    book: StatsBook | None = None,
) -> SourceStats:
    book = book or get_book(ctx)
    stats = SourceStats(plugin.name)

    reason = plugin.check(ctx)
    if reason:
        stats.status = SourceStatus.SKIPPED
        stats.error = reason
        book.begin(stats)
        book.finish(stats)
        return stats
    if ctx.out_of_time():
        stats.status = SourceStatus.SKIPPED
        stats.error = "time budget exhausted"
        book.begin(stats)
        book.finish(stats)
        return stats

    sem = semaphore or asyncio.Semaphore(1)
    async with sem:
        stats.status = SourceStatus.RUNNING
        stats.started_at = utcnow()
        t0 = time.monotonic()
        book.begin(stats)
        timeout = ctx.timeout_for(plugin.name, plugin.default_timeout)
        last_emit = t0
        try:
            async with asyncio.timeout(timeout):
                async for finding in plugin.run(ctx, target):
                    if finding is None:
                        continue
                    stats.found += 1
                    if ingest(ctx, finding, target):
                        stats.unique += 1
                    now = time.monotonic()
                    if stats.found % 50 == 0 or now - last_emit > 0.5:
                        stats.duration = now - t0
                        last_emit = now
                        book.progress(stats)
            stats.status = SourceStatus.DONE
        except SkipPlugin as exc:
            stats.status = SourceStatus.SKIPPED
            stats.error = str(exc)
        except TimeoutError:
            stats.status = SourceStatus.TIMEOUT
            stats.error = f"timed out after {int(timeout)}s"
        except HttpError as exc:
            # a third-party service that is unreachable or refuses anonymous clients is
            # "unavailable", not a failure of this run
            keyless = not (plugin.requires or {}).get("api_keys")
            if exc.status is None:
                stats.status = SourceStatus.SKIPPED
                stats.error = ctx.redact(f"unreachable: {exc}")[:200]
            elif exc.status in (401, 403) and keyless:
                stats.status = SourceStatus.SKIPPED
                stats.error = f"blocked (HTTP {exc.status})"
            else:
                stats.status = SourceStatus.ERROR
                stats.error = ctx.redact(f"{type(exc).__name__}: {exc}")[:300]
        except asyncio.CancelledError:
            stats.status = SourceStatus.ERROR
            stats.error = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001 - every error is captured per source
            stats.status = SourceStatus.ERROR
            stats.error = ctx.redact(f"{type(exc).__name__}: {exc}")[:300]
            log.debug("plugin %s failed", plugin.name, exc_info=True)
        finally:
            stats.duration = time.monotonic() - t0
            stats.finished_at = utcnow()
            book.finish(stats)
    return stats


async def run_plugins(
    plugins: Iterable[Plugin],
    ctx: RunContext,
    target: Target,
    *,
    concurrency: int | None = None,
) -> list[SourceStats]:
    """Run *plugins* for *target* concurrently; never raises for plugin errors."""
    plugin_list = sorted(plugins, key=lambda p: (-p.weight, p.name))
    if not plugin_list:
        return []
    sem = asyncio.Semaphore(max(1, concurrency or ctx.options.concurrency))
    book = get_book(ctx)
    results: list[SourceStats] = []
    async with asyncio.TaskGroup() as tg:
        tasks = [
            tg.create_task(
                run_plugin(p, ctx, target, semaphore=sem, book=book), name=f"plugin:{p.name}"
            )
            for p in plugin_list
        ]
    for t in tasks:
        results.append(t.result())
    return results


async def run_plugins_multi(
    plugins: Iterable[Plugin],
    ctx: RunContext,
    targets: Iterable[Target],
    *,
    concurrency: int | None = None,
) -> list[SourceStats]:
    """Run every plugin against every target (used for multi-root and recursion)."""
    plugin_list = list(plugins)
    target_list = list(targets)
    sem = asyncio.Semaphore(max(1, concurrency or ctx.options.concurrency))
    book = get_book(ctx)
    results: list[SourceStats] = []
    async with asyncio.TaskGroup() as tg:
        tasks = [
            tg.create_task(
                run_plugin(p, ctx, t, semaphore=sem, book=book), name=f"plugin:{p.name}:{t.root}"
            )
            for t in target_list
            for p in plugin_list
        ]
    for task in tasks:
        results.append(task.result())
    return results
