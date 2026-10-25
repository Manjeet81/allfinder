"""Wildcard logic, massdns parsers, data-file manager and the resolve stage (fake pool)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from allfinder.core.config import Config
from allfinder.core.dns import massresolve
from allfinder.core.dns.massdns_parse import parse_any, parse_massdns_json, parse_massdns_simple
from allfinder.core.dns.wildcard import WildcardDetector, answer_set, filter_wildcards, random_label
from allfinder.core.models import Finding, Resolution, SourceStatus
from allfinder.core.runner import get_book
from allfinder.core.wordlists import (
    DEFAULT_RESOLVERS,
    doctor_files,
    load_resolvers,
    wordlist_for_tier,
)


class FakeZone:
    """Answers like a DNS zone: explicit records + optional wildcard per parent."""

    def __init__(
        self, records: dict[str, list[str]], wildcards: dict[str, list[str]] | None = None
    ):
        self.records = records
        self.wildcards = wildcards or {}
        self.queries: list[str] = []

    async def resolve(self, host: str) -> Resolution:
        self.queries.append(host)
        if host in self.records:
            vals = self.records[host]
            return Resolution(
                host,
                a=[v for v in vals if v[0].isdigit()],
                cname=[v for v in vals if not v[0].isdigit()],
            )
        parts = host.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.wildcards:
                vals = self.wildcards[parent]
                return Resolution(
                    host,
                    a=[v for v in vals if v[0].isdigit()],
                    cname=[v for v in vals if not v[0].isdigit()],
                )
        return Resolution(host)

    async def resolve_many(self, hosts, *, on_result=None, cancel=None):
        out = {}
        for h in hosts:
            r = await self.resolve(h)
            out[h] = r
            if on_result:
                on_result(r)
        return out

    async def resolve_trusted(self, host: str) -> Resolution:
        return await self.resolve(host)

    class stats:  # noqa: N801 - mimic ResolverStats attribute
        bad_resolvers: set[str] = set()


def test_random_label_and_answer_set() -> None:
    assert len(random_label()) == 12 and random_label() != random_label()
    r = Resolution("a.example.com", a=["1.1.1.1"], cname=["CDN.example.net."])
    assert answer_set(r) == {"1.1.1.1", "cdn.example.net"}


async def test_wildcard_detector_multilevel() -> None:
    zone = FakeZone(
        records={
            "www.example.com": ["1.1.1.1"],
            "real.dev.example.com": ["5.5.5.5"],
            "same.dev.example.com": ["9.9.9.9"],  # same as wildcard -> wildcard-only
            "api.example.com": ["1.2.3.4", "cdn.example.net"],
        },
        wildcards={"dev.example.com": ["9.9.9.9"], "example.com": ["1.2.3.4"]},
    )
    det = WildcardDetector(zone.resolve, tests=3)
    hosts = [
        "www.example.com",
        "real.dev.example.com",
        "same.dev.example.com",
        "x.dev.example.com",
        "api.example.com",
        "random.example.com",
    ]
    await det.probe_all(hosts, "example.com")
    assert set(det.wildcard_zones) == {"example.com", "dev.example.com"}
    assert det.wildcard_zones["dev.example.com"] == {"9.9.9.9"}
    res = {h: await zone.resolve(h) for h in hosts}
    assert not await det.is_wildcard_only(res["www.example.com"], "example.com")
    assert not await det.is_wildcard_only(res["real.dev.example.com"], "example.com")
    assert await det.is_wildcard_only(res["same.dev.example.com"], "example.com")
    assert await det.is_wildcard_only(res["x.dev.example.com"], "example.com")
    assert await det.is_wildcard_only(res["random.example.com"], "example.com")
    # api has an extra CNAME answer not explained by the wildcard
    assert not await det.is_wildcard_only(res["api.example.com"], "example.com")
    assert det.classify_sync(res["x.dev.example.com"], "example.com")
    assert not det.classify_sync(Resolution("example.com", a=["1.2.3.4"]), "example.com")
    # cached: probing again does not re-query
    n = len(zone.queries)
    await det.probe("example.com")
    assert len(zone.queries) == n


def test_filter_wildcards_pure() -> None:
    wc = {"example.com": frozenset({"1.2.3.4"})}
    rs = [
        Resolution("a.example.com", a=["1.2.3.4"]),
        Resolution("b.example.com", a=["1.2.3.4", "5.6.7.8"]),
        Resolution("c.example.com"),
        Resolution("example.com", a=["1.2.3.4"]),
    ]
    out = filter_wildcards(rs, wc, "example.com")
    assert [r.wildcard for r in out] == [True, False, False, False]


def test_massdns_parsers() -> None:
    js = [
        '{"name":"a.example.com.","type":"A","class":"IN","status":"NOERROR","data":{"answers":[{"ttl":60,"type":"CNAME","class":"IN","name":"a.example.com.","data":"b.example.net."},{"ttl":60,"type":"A","class":"IN","name":"b.example.net.","data":"1.2.3.4"}]}}',
        '{"name":"nx.example.com.","type":"A","class":"IN","status":"NXDOMAIN","data":{}}',
        "garbage",
    ]
    out = parse_massdns_json(js)
    assert out["a.example.com"].a == ["1.2.3.4"] and out["a.example.com"].cname == ["b.example.net"]
    assert not out["nx.example.com"].resolved and out["nx.example.com"].error == "NXDOMAIN"
    simple = [
        "a.example.com. A 1.1.1.1",
        "a.example.com. AAAA ::1",
        "c.example.com. CNAME d.example.net.",
        "short",
    ]
    out2 = parse_massdns_simple(simple)
    assert out2["a.example.com"].ips == ["1.1.1.1", "::1"]
    assert out2["c.example.com"].cname == ["d.example.net"]
    assert parse_any(simple).keys() == out2.keys()
    assert parse_any(js).keys() == out.keys()


def test_wordlists_helpers(tmp_path: Path) -> None:
    cfg = Config()
    cfg.data_dir = tmp_path
    assert load_resolvers(cfg) == DEFAULT_RESOLVERS
    custom = tmp_path / "r.txt"
    custom.write_text("# comment\n9.9.9.9\n\n1.1.1.1\n")
    assert load_resolvers(cfg, str(custom)) == ["9.9.9.9", "1.1.1.1"]
    assert wordlist_for_tier(cfg, "none") is None
    assert wordlist_for_tier(cfg, f"custom:{custom}") == custom
    assert wordlist_for_tier(cfg, "custom:/nope/x.txt") is None
    assert wordlist_for_tier(cfg, "medium") is None  # not downloaded
    rows = doctor_files(cfg)
    assert any(name == "resolvers" and not ok for name, ok, _ in rows)


async def test_resolve_stage_with_fake_pool(ctx) -> None:
    zone = FakeZone(
        records={
            "www.example.com": ["1.1.1.1"],
            "api.example.com": ["2.2.2.2", "edge.example.net"],
        },
        wildcards={"example.com": ["7.7.7.7"]},
    )
    ctx.resolver_pool = zone  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    for h in ("www.example.com", "api.example.com", "ghost.example.com", "dead.example.com"):
        ctx.store.add_finding(Finding(h, "t"), root="example.com")
    ctx.store.add_finding(Finding("other.net", "t"), root="example.com", in_scope=False)
    await massresolve.resolve_stage(ctx)
    www, api, ghost, dead = (
        ctx.store.get(h)
        for h in ("www.example.com", "api.example.com", "ghost.example.com", "dead.example.com")
    )
    assert www.resolved and www.ips == ["1.1.1.1"] and not www.wildcard  # type: ignore[union-attr]
    assert api.resolved and api.cname == "edge.example.net"  # type: ignore[union-attr]
    assert ghost.wildcard and not ghost.resolved  # type: ignore[union-attr]
    assert dead.wildcard and not dead.resolved  # type: ignore[union-attr]
    assert "other.net" not in zone.queries
    stats = {s.source: s for s in get_book(ctx).all()}["resolve"]
    assert stats.status is SourceStatus.DONE and stats.found == 4 and stats.unique == 2
    assert ctx.store.counts()["resolved"] == 2 and ctx.store.counts()["wildcard"] == 2
    # second call: nothing pending
    assert massresolve.pending_hosts(ctx) == []
    ctx.store.add_finding(Finding("new.example.com", "t"), root="example.com")
    assert massresolve.pending_hosts(ctx) == ["new.example.com"]


async def test_keep_wildcards_option(ctx) -> None:
    zone = FakeZone(records={}, wildcards={"example.com": ["7.7.7.7"]})
    ctx.resolver_pool = zone  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    ctx.options.keep_wildcards = True
    ctx.store.add_finding(Finding("ghost.example.com", "t"), root="example.com")
    await massresolve.resolve_stage(ctx)
    g = ctx.store.get("ghost.example.com")
    assert g.wildcard and g.resolved  # type: ignore[union-attr]


async def test_validate_hits_drops_unconfirmed(ctx) -> None:
    class Flaky(FakeZone):
        async def resolve_trusted(self, host: str) -> Resolution:
            return Resolution(host)  # trusted resolvers see nothing

    zone = Flaky(records={"a.example.com": ["1.1.1.1"]})
    ctx.resolver_pool = zone  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    ctx.store.add_finding(Finding("a.example.com", "t"), root="example.com")
    res = await massresolve.resolve_hosts(
        ctx, ["a.example.com"], root="example.com", validate_hits=True
    )
    assert not res["a.example.com"].resolved
    assert not ctx.store.get("a.example.com").resolved  # type: ignore[union-attr]


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ALLFINDER_LIVE"), reason="set ALLFINDER_LIVE=1")
async def test_live_resolver_pool() -> None:
    from allfinder.core.dns.resolver_pool import ResolverPool, validate_resolvers

    # note: networks with transparent DNS interception answer for any IP, so only
    # assert that the well-known resolvers pass validation
    good = await validate_resolvers(["1.1.1.1", "8.8.8.8"])
    assert "1.1.1.1" in good
    pool = ResolverPool(good, qps=50)
    res = await pool.resolve("www.github.com")
    assert res.resolved and res.cname == ["github.com"] and res.a
    assert not (await pool.resolve(f"{random_label()}.example.com")).resolved
    ns = await pool.records("example.com", "NS")
    assert ns
    pool.close()
