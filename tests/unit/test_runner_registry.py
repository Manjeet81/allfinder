import pytest

from allfinder.core.models import SourceKind, SourceStatus, Target
from allfinder.core.registry import Registry, UnknownSourceError
from allfinder.core.runner import get_book, run_plugins, run_plugins_multi
from tests.conftest import FakeFailing, FakeNeedsKey, FakePassive, FakeSlow


def test_registry_select(fake_registry: Registry) -> None:
    reg = fake_registry
    assert reg.has("crtsh") and reg.has("fake")
    names = [p.name for p in reg.select(use=["test"])]
    assert set(names) == {"fake", "fakefail", "fakeslow", "fakekeyed"}
    assert [p.name for p in reg.select(use=["fake,fakeslow"], exclude=["fakeslow"])] == ["fake"]
    assert [p.name for p in reg.select(use=["test"], exclude=["keyed"])] == sorted(
        ["fake", "fakefail", "fakeslow"]
    )
    # kind token + kinds filter
    assert all(p.kind is SourceKind.PASSIVE for p in reg.select(use=["passive"]))
    assert reg.select(use=["test"], kinds=[SourceKind.ACTIVE]) == []
    # config disabled applies unless explicitly used
    assert "fake" not in [p.name for p in reg.select(use=["test"], disabled=["fake"])]
    assert "fake" in [p.name for p in reg.select(use=["fake"], disabled=["fake"])]
    with pytest.raises(UnknownSourceError):
        reg.select(use=["nope"])
    with pytest.raises(UnknownSourceError):
        reg.get("nope")
    assert "test" in reg.tags()
    assert reg.get("fake").name == "fake"


def test_registry_register_requires_name() -> None:
    from allfinder.plugins.base import Plugin

    class NoName(Plugin):
        async def run(self, ctx, target):  # pragma: no cover
            yield None

    with pytest.raises(ValueError):
        Registry().register(NoName)


async def test_runner_collects_everything(ctx, fake_registry: Registry) -> None:
    seen: list[tuple[str, bool]] = []
    ctx.on_finding = lambda f, new: seen.append((f.hostname, new))
    stats_events: list[str] = []
    ctx.on_stats = lambda s: stats_events.append(f"{s.source}:{s.status.value}")

    target = Target("example.com")
    ctx.config.sources.timeouts["fakeslow"] = 1
    plugins = [FakePassive(), FakeFailing(), FakeSlow(), FakeNeedsKey()]
    ctx.keys = type(ctx.keys)({})  # drop keys -> fakekeyed is skipped
    results = {s.source: s for s in await run_plugins(plugins, ctx, target)}

    ok = results["fake"]
    assert ok.status is SourceStatus.DONE
    assert ok.found == 4  # 'bad name' dropped by normalization, evil.net kept as related
    assert ok.unique == 4
    assert results["fakefail"].status is SourceStatus.ERROR
    assert "boom" in (results["fakefail"].error or "")
    assert results["fakefail"].found == 1  # partial results kept
    assert results["fakeslow"].status is SourceStatus.TIMEOUT
    assert results["fakeslow"].found == 1
    assert results["fakekeyed"].status is SourceStatus.SKIPPED
    assert "no API key" in (results["fakekeyed"].error or "")

    hosts = ctx.store.hostnames()
    assert hosts == sorted(
        [
            "a.example.com",
            "b.example.com",
            "c.example.com",
            "partial.example.com",
            "slow.example.com",
        ]
    )
    assert ctx.store.related_domains() == ["evil.net"]
    # on_finding only fires for in-scope names
    assert ("evil.net", True) not in seen
    assert ("a.example.com", True) in seen
    assert "fake:running" in stats_events and "fake:done" in stats_events
    # stats were persisted
    persisted = {s.source: s for s in ctx.store.stats()}
    assert persisted["fake"].unique == 4
    assert persisted["fakeslow"].status is SourceStatus.TIMEOUT
    book = get_book(ctx)
    assert {s.source for s in book.errors()} == {"fakefail", "fakeslow"}


async def test_runner_redacts_keys_in_errors(ctx) -> None:
    results = await run_plugins([FakeFailing()], ctx, Target("example.com"))
    assert "secret-key-123" not in (results[0].error or "")
    assert "***" in (results[0].error or "")


async def test_runner_multi_target_aggregates(ctx) -> None:
    targets = [Target("example.com"), Target("api.example.com", roots=("example.com",), depth=1)]
    await run_plugins_multi([FakePassive()], ctx, targets)
    book = get_book(ctx)
    merged = {s.source: s for s in book.all()}["fake"]
    assert merged.found == 8
    assert merged.unique == 4  # second target finds the same names
    assert merged.status is SourceStatus.DONE


async def test_runner_time_budget(ctx) -> None:
    ctx.options.max_time = 0.0
    results = await run_plugins([FakePassive()], ctx, Target("example.com"))
    assert results[0].status is SourceStatus.SKIPPED
