"""End-to-end pipeline + recursion with fake plugins and a fake resolver pool."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from allfinder.core.models import Finding, SourceKind, Target
from allfinder.core.pipeline import EXIT_OK, EXIT_SOURCE_ERRORS, Pipeline
from allfinder.plugins.base import Plugin


class SeedPassive(Plugin):
    name = "seed"
    kind = SourceKind.PASSIVE
    tags = ("test",)
    recursive = True
    emit = {
        "example.com": [
            "api.example.com",
            "www.example.com",
            "v1.api.example.com",
            "v2.api.example.com",
        ],
        "api.example.com": ["internal.api.example.com"],  # discovered during recursion
    }

    async def run(self, ctx, target: Target) -> AsyncIterator[Finding]:
        for h in self.emit.get(target.root, []):
            f = self.finding(h)
            if f:
                yield f


@pytest.fixture
def pipeline_registry(fake_registry):
    fake_registry.register(SeedPassive)
    yield fake_registry
    fake_registry._plugins.pop("seed", None)


def _fake_pool_records() -> dict:
    return {
        "api.example.com": ["1.1.1.1"],
        "www.example.com": ["1.1.1.2"],
        "v1.api.example.com": ["1.1.1.3"],
        "v2.api.example.com": ["1.1.1.4"],
        "internal.api.example.com": ["10.0.0.1"],
    }


async def test_pipeline_passive_and_resolve(ctx, pipeline_registry) -> None:
    from tests.unit.test_dns import FakeZone

    ctx.options.use = ["seed"]
    ctx.options.skip_resolve = False
    ctx.options.depth = 0
    ctx.resolver_pool = FakeZone(records=_fake_pool_records())  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    result = await Pipeline(ctx, pipeline_registry).run()
    assert result.exit_code == EXIT_OK
    assert result.counts["total"] == 4
    assert result.counts["resolved"] == 4
    # report files written
    assert (ctx.out_dir / "subdomains.txt").read_text().split() == [
        "api.example.com",
        "v1.api.example.com",
        "v2.api.example.com",
        "www.example.com",
    ]
    assert "resolve" in {
        s.source
        for s in __import__("allfinder.core.runner", fromlist=["get_book"]).get_book(ctx).all()
    }


async def test_pipeline_recursion(ctx, pipeline_registry) -> None:
    from tests.unit.test_dns import FakeZone

    ctx.options.use = ["seed"]
    ctx.options.skip_resolve = False
    ctx.options.depth = 1
    ctx.options.permute = False
    ctx.options.recursion_min_children = 2  # api has 2 children -> becomes sub-root
    ctx.resolver_pool = FakeZone(records=_fake_pool_records())  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    result = await Pipeline(ctx, pipeline_registry).run()
    # recursion treats api.example.com as a sub-root and finds internal.api.example.com
    assert "internal.api.example.com" in ctx.store.hostnames()
    assert result.counts["total"] == 5


async def test_pipeline_interrupt_writes_partial(ctx, pipeline_registry, monkeypatch) -> None:
    ctx.options.use = ["seed"]
    ctx.options.skip_resolve = True
    ctx.options.depth = 0

    async def boom(self, targets):
        from allfinder.core.runner import run_plugins_multi

        await run_plugins_multi(
            [SeedPassive()], self.ctx, [Target("example.com", roots=("example.com",))]
        )
        raise KeyboardInterrupt

    # simulate Ctrl+C mid-run via CancelledError path
    import asyncio

    async def cancel_stage(self, targets):
        from allfinder.core.runner import run_plugins_multi

        await run_plugins_multi(
            [SeedPassive()], self.ctx, [Target("example.com", roots=("example.com",))]
        )
        raise asyncio.CancelledError

    monkeypatch.setattr(Pipeline, "stage_passive", cancel_stage)
    result = await Pipeline(ctx, pipeline_registry).run()
    assert result.interrupted and result.exit_code == 130
    # partial results still on disk
    assert ctx.store.hostnames()  # seed names were stored before the cancel
    assert (ctx.out_dir / "subdomains.txt").is_file()


async def test_pipeline_reports_source_errors(ctx, fake_registry) -> None:
    ctx.options.use = ["fakefail"]
    ctx.options.skip_resolve = True
    ctx.options.depth = 0
    result = await Pipeline(ctx, fake_registry).run()
    assert result.exit_code == EXIT_SOURCE_ERRORS
    assert any("fakefail" in e for e in result.errors)
