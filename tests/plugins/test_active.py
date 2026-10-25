"""Active techniques: permutation engine, brute force, record mining, reverse DNS, webscrape."""

from __future__ import annotations

import httpx
import pytest
import respx

from allfinder.core.models import Finding, Resolution, Target
from allfinder.plugins.active import permutation as permmod
from allfinder.plugins.active.bruteforce import BruteForce, _candidates
from allfinder.plugins.active.permutation import Permutation, generate, permute_label, tokenize
from allfinder.plugins.active.records import RecordMiner
from allfinder.plugins.active.reverse_dns import ReverseDns
from allfinder.plugins.active.webscrape import WebScrape
from tests.unit.test_dns import FakeZone

T = Target("example.com")


# --------------------------------------------------------------------------- permutation (pure)


def test_tokenize_and_permute_label() -> None:
    assert tokenize(["api-dev", "web01", "us_east"]) >= {"api", "dev", "web", "01", "us", "east"}
    out = permute_label("api", ["dev", "v2"])
    assert "dev-api" in out and "api-dev" in out and "dev.api" in out and "api" not in out
    nums = permute_label("web01", [])
    assert "web02" in nums and "web00" in nums and "web1" in nums


def test_generate_bounded_and_scoped() -> None:
    cands = generate(["api.example.com", "v1.api.example.com"], ["example.com"], max_results=5000)
    assert all(c.endswith(".example.com") for c in cands)
    assert "dev-api.example.com" in cands
    assert "dev.api.example.com" in cands
    small = generate(["api.example.com"], ["example.com"], max_results=10)
    assert len(small) <= 10
    assert generate(["example.com"], ["example.com"]) == set()  # apex only -> nothing


# --------------------------------------------------------------------------- permutation plugin


async def test_permutation_plugin_resolves(ctx) -> None:
    ctx.store.add_finding(Finding("api.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(Resolution("api.example.com", a=["1.1.1.1"]))
    zone = FakeZone(
        records={"dev-api.example.com": ["2.2.2.2"], "api-dev.example.com": ["3.3.3.3"]}
    )
    ctx.resolver_pool = zone  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    found = sorted({f.hostname async for f in Permutation().run(ctx, T)})
    assert "dev-api.example.com" in found and "api-dev.example.com" in found
    assert all(f.endswith(".example.com") for f in found)


async def test_permutation_disabled(ctx) -> None:
    ctx.options.permute = False
    assert [f async for f in Permutation().run(ctx, T)] == []


async def test_permutation_no_resolved_names(ctx) -> None:
    ctx.resolver_pool = FakeZone(records={})  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    assert [f async for f in Permutation().run(ctx, T)] == []


# --------------------------------------------------------------------------- brute force


def test_brute_candidates(tmp_path) -> None:
    wl = tmp_path / "w.txt"
    wl.write_text("# comment\nwww\nAPI\nwww\n\nbad word\nexample.com\n")
    cands = list(_candidates(wl, "example.com"))
    assert cands == ["www.example.com", "api.example.com", "example.com"]


async def test_bruteforce_skips_without_wordlist(ctx) -> None:
    from allfinder.plugins.base import SkipPlugin

    ctx.options.brute = "medium"  # not downloaded
    with pytest.raises(SkipPlugin):
        _ = [f async for f in BruteForce().run(ctx, T)]
    ctx.options.brute = "none"
    assert [f async for f in BruteForce().run(ctx, T)] == []


async def test_bruteforce_native(ctx, tmp_path) -> None:
    wl = tmp_path / "w.txt"
    wl.write_text("www\napi\nmissing\n")
    ctx.options.brute = f"custom:{wl}"
    zone = FakeZone(records={"www.example.com": ["1.1.1.1"], "api.example.com": ["2.2.2.2"]})
    ctx.resolver_pool = zone  # type: ignore[assignment]
    ctx.extras["force_native_resolver"] = True
    found = sorted({f.hostname async for f in BruteForce().run(ctx, T)})
    assert found == ["api.example.com", "www.example.com"]


# --------------------------------------------------------------------------- record mining


async def test_record_miner(ctx, monkeypatch) -> None:
    answers = {
        ("example.com", "NS"): ["ns1.example.com.", "ns2.example.net."],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "SOA"): ["ns1.example.com. hostmaster.example.com. 1 2 3 4 5"],
        ("example.com", "TXT"): ["v=spf1 include:_spf.example.com include:spf.partner.net -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; rua=mailto:x@rua.example.com"],
    }

    class RecPool:
        async def records(self, host, qtype):
            return answers.get((host, qtype), [])

        async def resolve(self, host):
            return Resolution(host)

    monkeypatch.setattr(permmod, "generate", permmod.generate)  # noop keep import
    monkeypatch.setattr("allfinder.core.dns.massresolve.get_pool", lambda c: RecPool())
    ctx.store.add_finding(Finding("app.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(
        Resolution("app.example.com", a=["1.1.1.1"], cname=["edge.example.com"])
    )
    found = sorted({f.hostname async for f in RecordMiner().run(ctx, T)})
    assert "ns1.example.com" in found  # NS
    assert "mail.example.com" in found  # MX
    assert "_spf.example.com" in found  # SPF include
    assert "edge.example.com" in found  # CNAME chain
    # out-of-scope related infra (partner SPF, external NS) is emitted too -> related_domains
    assert "spf.partner.net" in found


# --------------------------------------------------------------------------- reverse DNS


async def test_reverse_dns(ctx) -> None:
    ctx.store.add_finding(Finding("a.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(Resolution("a.example.com", a=["93.184.216.34"]))

    class PtrPool:
        async def records(self, host, qtype):
            # only .34 has a PTR back into scope
            if host.startswith("34.216.184.93"):
                return ["host34.example.com."]
            if host.startswith("35.216.184.93"):
                return ["other.net."]
            return []

    ctx.resolver_pool = PtrPool()  # type: ignore[assignment]
    import allfinder.core.dns.massresolve as mr

    orig = mr.get_pool
    mr.get_pool = lambda c: PtrPool()  # type: ignore[assignment]
    try:
        found = sorted({f.hostname async for f in ReverseDns().run(ctx, T)})
    finally:
        mr.get_pool = orig
    assert "host34.example.com" in found
    assert "other.net" not in found  # out of scope PTR ignored by finding()


async def test_reverse_dns_skips_private_ips(ctx) -> None:
    ctx.store.add_finding(Finding("a.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(Resolution("a.example.com", a=["10.0.0.5"]))
    assert [f async for f in ReverseDns().run(ctx, T)] == []


# --------------------------------------------------------------------------- web scrape


@respx.mock
async def test_webscrape(ctx) -> None:
    ctx.store.add_finding(Finding("www.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(Resolution("www.example.com", a=["1.1.1.1"]))
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={"content-security-policy": "default-src https://cdn.example.com"},
            text='<a href="https://blog.example.com/x">b</a><script src="/app.js"></script>',
        )
    )
    respx.get("https://www.example.com/app.js").mock(
        return_value=httpx.Response(200, text='var api="https://api.example.com/v1";')
    )
    for path in (
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/.well-known/security.txt",
        "/crossdomain.xml",
        "/humans.txt",
    ):
        respx.get(f"https://www.example.com{path}").mock(
            return_value=httpx.Response(
                200,
                text="Sitemap: https://static.example.com/sitemap.xml"
                if "sitemap" in path
                else "ok",
            )
        )
    found = sorted({f.hostname async for f in WebScrape().run(ctx, T)})
    assert {"cdn.example.com", "blog.example.com", "api.example.com", "static.example.com"} <= set(
        found
    )
    assert all(h.endswith(".example.com") for h in found)


# --------------------------------------------------------------------------- AXFR / NSEC


async def test_axfr_parses_transferred_zone(ctx, monkeypatch) -> None:
    import dns.name
    import dns.zone

    from allfinder.plugins.active.records import AxfrNsec

    class NsPool:
        async def records(self, host, qtype):
            return ["ns1.example.com."] if qtype == "NS" else []

        async def resolve(self, host):
            return Resolution(host, a=["1.2.3.4"])

    monkeypatch.setattr("allfinder.core.dns.massresolve.get_pool", lambda c: NsPool())

    async def fake_do_xfr(self, zone, name, ip):
        zone.find_node(dns.name.from_text("api.example.com."), create=True)
        zone.find_node(dns.name.from_text("mail.example.com."), create=True)

    monkeypatch.setattr(AxfrNsec, "_do_xfr", fake_do_xfr)
    found = sorted({f.hostname async for f in AxfrNsec().run(ctx, T)})
    assert "api.example.com" in found and "mail.example.com" in found


async def test_axfr_no_nameservers_is_quiet(ctx, monkeypatch) -> None:
    from allfinder.plugins.active.records import AxfrNsec

    class EmptyPool:
        async def records(self, host, qtype):
            return []

        async def resolve(self, host):
            return Resolution(host)

    monkeypatch.setattr("allfinder.core.dns.massresolve.get_pool", lambda c: EmptyPool())
    assert [f async for f in AxfrNsec().run(ctx, T)] == []
