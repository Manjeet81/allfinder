"""Shared fixtures: an in-memory RunContext and a fake plugin registry."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from allfinder.core.config import Config, HttpConfig, KeyRing
from allfinder.core.context import RunContext, RunOptions
from allfinder.core.http import RateLimiter, make_client
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.core.normalize import Scope
from allfinder.core.store import Store
from allfinder.plugins.base import Plugin


class FakePassive(Plugin):
    name = "fake"
    kind = SourceKind.PASSIVE
    description = "test plugin"
    tags = ("test",)
    recursive = True
    hosts: list[str] = ["a.example.com", "B.example.com", "*.c.example.com", "evil.net", "bad name"]

    async def run(self, ctx, target: Target) -> AsyncIterator[Finding]:
        for h in self.hosts:
            f = self.finding(h)
            if f:
                yield f


class FakeFailing(Plugin):
    name = "fakefail"
    kind = SourceKind.PASSIVE
    tags = ("test",)

    async def run(self, ctx, target: Target) -> AsyncIterator[Finding]:
        yield Finding("partial.example.com", self.name)
        raise RuntimeError("boom secret-key-123")


class FakeSlow(Plugin):
    name = "fakeslow"
    kind = SourceKind.PASSIVE
    tags = ("test",)
    default_timeout = 1

    async def run(self, ctx, target: Target) -> AsyncIterator[Finding]:
        yield Finding("slow.example.com", self.name)
        await asyncio.sleep(30)
        yield Finding("never.example.com", self.name)


class FakeNeedsKey(Plugin):
    name = "fakekeyed"
    kind = SourceKind.PASSIVE
    tags = ("test", "keyed")
    requires = {"api_keys": ["fakeprovider"]}

    async def run(self, ctx, target: Target) -> AsyncIterator[Finding]:
        yield Finding("keyed.example.com", self.name)


FAKE_PLUGINS = [FakePassive, FakeFailing, FakeSlow, FakeNeedsKey]


@pytest.fixture
def fake_registry():
    from allfinder.core.registry import get_registry

    reg = get_registry()
    reg.discover()
    for cls in FAKE_PLUGINS:
        reg.register(cls)
    yield reg
    for cls in FAKE_PLUGINS:
        reg._plugins.pop(cls.name, None)


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[RunContext]:
    cfg = Config()
    cfg.data_dir = tmp_path / "data"
    cfg.http.backoff = 0.01
    store = Store()
    run = store.start_run(["example.com"], version="test")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    tmpdir = out_dir / "tmp"
    tmpdir.mkdir()
    async with make_client(HttpConfig(timeout=5, retries=0)) as client:
        yield RunContext(
            config=cfg,
            options=RunOptions(timeout_per_source=5, skip_resolve=True),
            limiter=RateLimiter(enabled=False),
            scope=Scope(["example.com"]),
            keys=KeyRing({"fakeprovider": ["secret-key-123"]}),
            http=client,
            store=store,
            run=run,
            out_dir=out_dir,
            tmpdir=tmpdir,
        )
    store.close()


pytest_plugins = ["tests.fakebin"]
