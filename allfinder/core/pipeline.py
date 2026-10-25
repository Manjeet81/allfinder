"""Stage scheduler: passive -> resolve -> active -> recurse -> enrich -> report.

Later stages feed earlier ones (bounded by ``--depth`` and ``--max-time``).
Every stage is tolerant: a failing plugin only marks its own source as
errored; Ctrl+C stops the stages and still writes the reports.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from allfinder.core.context import RunContext
from allfinder.core.models import SourceKind, SourceStatus, Target
from allfinder.core.registry import Registry, get_registry
from allfinder.core.runner import get_book, run_plugins_multi
from allfinder.plugins.base import Plugin
from allfinder.report import write_all_reports

if TYPE_CHECKING:
    from allfinder.cli.ui import UI

log = logging.getLogger("allfinder.pipeline")

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_SOURCE_ERRORS = 2
EXIT_INTERRUPTED = 130


@dataclass(slots=True)
class PipelineResult:
    exit_code: int = EXIT_OK
    files: dict[str, Path] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    interrupted: bool = False
    errors: list[str] = field(default_factory=list)


class Pipeline:
    def __init__(
        self, ctx: RunContext, registry: Registry | None = None, ui: UI | None = None
    ) -> None:
        self.ctx = ctx
        self.registry = registry or get_registry()
        self.ui = ui
        self.targets: list[Target] = [
            Target(root=r, roots=tuple(ctx.scope.roots), depth=0) for r in ctx.scope.roots
        ]

    # ------------------------------------------------------------------ selection
    def select(self, kind: SourceKind) -> list[Plugin]:
        opts = self.ctx.options
        exclude = list(opts.exclude)
        # --use / --exclude filter each stage independently.  A --use list that
        # names nothing of *this* kind (e.g. `--use crtsh` with --probe) must not
        # suppress the stage: the active/enrich stages are gated by --active/--probe,
        # so fall back to this kind's defaults when --use is passive-only.
        use = [u for u in opts.use if self.registry.names_kind(u, kind)] if opts.use else []
        if (
            kind is SourceKind.PASSIVE
            and not use
            and not opts.search_engines
            and "searchengines" in self.registry.tags()
        ):
            exclude.append("searchengines")
        return self.registry.select(
            use=use or None,
            exclude=exclude,
            kinds=[kind],
            disabled=self.ctx.config.sources.disabled,
        )

    # ------------------------------------------------------------------ stages
    async def stage_passive(self, targets: list[Target]) -> None:
        plugins = self.select(SourceKind.PASSIVE)
        if not plugins:
            self.ctx.notice("no passive sources selected", "warning")
            return
        self.ctx.log.info("passive stage: %d sources x %d targets", len(plugins), len(targets))
        await run_plugins_multi(plugins, self.ctx, targets)

    async def stage_resolve(self) -> None:
        """Wildcard detection + mass resolution (implemented in the DNS phase)."""
        try:
            from allfinder.core.dns.massresolve import resolve_stage
        except ImportError:
            self.ctx.log.debug("resolve stage not available")
            return
        await resolve_stage(self.ctx)

    async def stage_active(self, targets: list[Target]) -> None:
        plugins = self.select(SourceKind.ACTIVE)
        if not plugins:
            return
        self.ctx.log.info("active stage: %d techniques", len(plugins))
        await run_plugins_multi(plugins, self.ctx, targets)
        await self.stage_resolve()

    async def stage_recurse(self) -> None:
        try:
            from allfinder.core.recursion import recursion_rounds
        except ImportError:
            return
        await recursion_rounds(self)

    async def stage_enrich(self) -> None:
        plugins = self.select(SourceKind.ENRICH)
        if not plugins:
            return
        self.ctx.log.info("enrich stage: %d plugins", len(plugins))
        await run_plugins_multi(plugins, self.ctx, self.targets)

    # ------------------------------------------------------------------ run
    async def run(self) -> PipelineResult:
        ctx = self.ctx
        opts = ctx.options
        result = PipelineResult()
        t0 = time.monotonic()
        try:
            await self.stage_passive(self.targets)
            if not opts.skip_resolve and not ctx.out_of_time():
                await self.stage_resolve()
            if opts.active and not opts.passive_only and not ctx.out_of_time():
                await self.stage_active(self.targets)
            if opts.depth > 0 and not opts.passive_only and not ctx.out_of_time():
                await self.stage_recurse()
            if opts.probe and not ctx.out_of_time():
                await self.stage_enrich()
        except asyncio.CancelledError:
            result.interrupted = True
            ctx.cancel.set()
            task = asyncio.current_task()
            if task is not None:
                task.uncancel()
            log.warning("interrupted; writing partial results")
        finally:
            result = self._finish(result, time.monotonic() - t0)
        return result

    def _finish(self, result: PipelineResult, elapsed: float) -> PipelineResult:
        ctx = self.ctx
        ctx.store.flush()
        ctx.store.finish_run()
        book = get_book(ctx)
        stats = book.all()
        subs = ctx.store.subdomains(ctx.scope.roots)
        related = ctx.store.related_domains(ctx.scope.roots)
        counts = ctx.store.counts(ctx.scope.roots)
        try:
            result.files = write_all_reports(
                ctx.out_dir, subs=subs, related=related, stats=stats, run=ctx.run, counts=counts
            )
        except OSError as exc:
            log.error("could not write reports: %s", exc)
        result.counts = counts
        result.errors = [
            f"{s.source}: {s.error}"
            for s in stats
            if s.status in (SourceStatus.ERROR, SourceStatus.TIMEOUT)
        ]
        if result.interrupted:
            result.exit_code = EXIT_INTERRUPTED
        elif result.errors:
            result.exit_code = EXIT_SOURCE_ERRORS
        else:
            result.exit_code = EXIT_OK
        if self.ui is not None:
            self.ui.stop()
            self.ui.summary(
                stats, counts, ctx.out_dir, elapsed=elapsed, interrupted=result.interrupted
            )
        if not ctx.options.keep_tmp:
            shutil.rmtree(ctx.tmpdir, ignore_errors=True)
        return result
