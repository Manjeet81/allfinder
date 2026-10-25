"""Enrichment plugins: httpx probe (binary + native), takeover, ipinfo."""

from __future__ import annotations

import json

import httpx
import respx

from allfinder.core.models import Finding, Resolution, Target
from allfinder.plugins.enrich.httpx_probe import HttpxProbe, NativeHttpProbe
from allfinder.plugins.enrich.ipinfo import IpInfo
from allfinder.plugins.enrich.takeover import Takeover, load_fingerprints

T = Target("example.com")


def _seed(ctx, host="app.example.com", ips=("1.1.1.1",), cname=None):
    ctx.store.add_finding(Finding(host, "seed"), root="example.com")
    ctx.store.update_resolution(Resolution(host, a=list(ips), cname=[cname] if cname else []))


async def test_httpx_binary(ctx, fakebins) -> None:
    _seed(ctx, "www.example.com")
    rec = {
        "input": "www.example.com",
        "url": "https://www.example.com",
        "status_code": 200,
        "title": "Home",
        "tech": ["nginx", "React"],
        "webserver": "nginx",
        "a": ["1.1.1.1"],
        "cname": ["edge.example.net"],
        "content_length": 1234,
    }
    fakebins.add("httpx", json.dumps(rec) + "\nnot json\n", read_stdin=True)
    found = [f async for f in HttpxProbe().run(ctx, T)]
    assert [f.hostname for f in found] == ["www.example.com"]
    sub = ctx.store.get("www.example.com")
    assert sub.http.status == 200 and sub.http.title == "Home"
    assert sub.http.tech == ["nginx", "React"] and sub.http.server == "nginx"
    assert sub.alive


async def test_httpx_native_only_without_binary(ctx) -> None:
    # no httpx binary present -> binary plugin is skipped, native runs
    assert HttpxProbe().check(ctx) is not None
    assert NativeHttpProbe().check(ctx) is None


@respx.mock
async def test_native_probe(ctx) -> None:
    _seed(ctx, "www.example.com")
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={"server": "nginx", "content-length": "99"},
            text="<html><head><title>Hi There</title></head></html>",
        )
    )
    found = [f async for f in NativeHttpProbe().run(ctx, T)]
    assert [f.hostname for f in found] == ["www.example.com"]
    sub = ctx.store.get("www.example.com")
    assert sub.http.status == 200 and sub.http.title == "Hi There" and sub.http.server == "nginx"
    assert sub.http.content_length == 99


@respx.mock
async def test_native_probe_https_fallback_to_http(ctx) -> None:
    _seed(ctx, "legacy.example.com")
    respx.get("https://legacy.example.com/").mock(side_effect=httpx.ConnectError("no tls"))
    respx.get("http://legacy.example.com/").mock(
        return_value=httpx.Response(200, text="<title>Plain</title>")
    )
    found = [f async for f in NativeHttpProbe().run(ctx, T)]
    assert found and ctx.store.get("legacy.example.com").http.title == "Plain"


def test_load_fingerprints_builtin_and_file(ctx, tmp_path) -> None:
    fps = load_fingerprints(ctx)
    assert any("github" in fp["service"].lower() for fp in fps)
    data_dir = ctx.config.data_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "takeover_fingerprints.json").write_text(
        json.dumps(
            [
                {
                    "service": "Custom",
                    "cname": ["custom.io"],
                    "fingerprint": "gone away",
                    "status": "Vulnerable",
                },
                {
                    "service": "Skip",
                    "cname": ["skip.io"],
                    "fingerprint": [],
                    "status": "Not vulnerable",
                },
            ]
        )
    )
    fps = load_fingerprints(ctx)
    assert any(fp["service"] == "Custom" for fp in fps)
    assert not any(fp["service"] == "Skip" for fp in fps)


@respx.mock
async def test_takeover_vulnerable_and_dangling(ctx) -> None:
    # dangling (unresolved) CNAME to GitHub Pages serving the fingerprint page
    ctx.store.add_finding(Finding("gone.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(Resolution("gone.example.com", cname=["user.github.io"]))
    respx.get("https://gone.example.com/").mock(
        return_value=httpx.Response(404, text="There isn't a GitHub Pages site here.")
    )
    findings = [f async for f in Takeover().run(ctx, T)]
    assert [f.hostname for f in findings] == ["gone.example.com"]
    sub = ctx.store.get("gone.example.com")
    assert sub.takeover["vulnerable"] is True and "GitHub" in sub.takeover["service"]


@respx.mock
async def test_takeover_not_vulnerable(ctx) -> None:
    ctx.store.add_finding(Finding("ok.example.com", "seed"), root="example.com")
    ctx.store.update_resolution(
        Resolution("ok.example.com", a=["1.1.1.1"], cname=["user.github.io"])
    )
    respx.get("https://ok.example.com/").mock(
        return_value=httpx.Response(200, text="<html>Real site</html>")
    )
    findings = [f async for f in Takeover().run(ctx, T)]
    assert findings == []  # resolved + no fingerprint -> not flagged
    assert ctx.store.get("ok.example.com").takeover["vulnerable"] is False


@respx.mock
async def test_ipinfo_batch(ctx) -> None:
    _seed(ctx, "a.example.com", ips=["1.1.1.1"])
    _seed(ctx, "b.example.com", ips=["1.1.1.1", "2.2.2.2"])
    route = respx.post("http://ip-api.com/batch").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "status": "success",
                    "query": "1.1.1.1",
                    "as": "AS13335 Cloudflare",
                    "org": "Cloudflare",
                },
                {"status": "success", "query": "2.2.2.2", "as": "AS3215 Orange", "org": "Orange"},
            ],
        )
    )
    _ = [f async for f in IpInfo().run(ctx, T)]
    assert route.called
    a = ctx.store.get("a.example.com")
    assert a.asn == "AS13335 Cloudflare" and a.org == "Cloudflare"
    b = ctx.store.get("b.example.com")
    assert b.asn in ("AS13335 Cloudflare", "AS3215 Orange")


async def test_ipinfo_no_ips(ctx) -> None:
    ctx.store.add_finding(Finding("x.example.com", "seed"), root="example.com")
    assert [f async for f in IpInfo().run(ctx, T)] == []
