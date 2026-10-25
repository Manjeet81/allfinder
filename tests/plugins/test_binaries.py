"""Binary wrappers tested against fake executables."""

from __future__ import annotations

from allfinder.core.models import Finding, Resolution, SourceStatus, Target
from allfinder.core.runner import run_plugins
from allfinder.plugins.active.bin_cero import Cero
from allfinder.plugins.passive.bin_amass import Amass
from allfinder.plugins.passive.bin_assetfinder import AssetFinder
from allfinder.plugins.passive.bin_findomain import Findomain
from allfinder.plugins.passive.bin_gau import Gau, WaybackUrls
from allfinder.plugins.passive.bin_keyed import ChaosBin, GithubSubdomains, Haktrails, Shosubgo
from allfinder.plugins.passive.bin_subfinder import Subfinder

T = Target("example.com")


async def collect(plugin, ctx) -> list[str]:
    return sorted({f.hostname async for f in plugin.run(ctx, T)})


async def test_missing_binary_is_skipped(ctx) -> None:
    ctx_binary = ctx.binary
    assert ctx_binary("definitely-not-installed-xyz") is None
    stats = await run_plugins([AssetFinder()], ctx, T) if ctx.binary("assetfinder") is None else []
    if stats:
        assert stats[0].status is SourceStatus.SKIPPED
        assert "binary not found" in (stats[0].error or "")


async def test_subfinder_json_and_plain(ctx, fakebins) -> None:
    fakebins.add(
        "subfinder",
        '{"host":"a.example.com","input":"example.com","source":"crtsh"}\n'
        '{"host":"b.example.com","ip":"1.2.3.4","source":"dnsdumpster"}\n'
        "c.example.com\n"
        "not json {\n",
    )
    found = [f async for f in Subfinder().run(ctx, T)]
    assert sorted(f.hostname for f in found) == ["a.example.com", "b.example.com", "c.example.com"]
    assert next(f for f in found if f.hostname == "b.example.com").ips == ["1.2.3.4"]
    assert next(f for f in found if f.hostname == "a.example.com").extra == {"via": "crtsh"}


async def test_amass_decorated_output(ctx, fakebins) -> None:
    fakebins.add(
        "amass",
        "www.example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)\n"
        "api.example.com (FQDN) --> cname_record --> edge.example.net (FQDN)\n"
        "mail.example.com\n",
    )
    assert await collect(Amass(), ctx) == ["api.example.com", "mail.example.com", "www.example.com"]


async def test_assetfinder_findomain_plain(ctx, fakebins) -> None:
    fakebins.add("assetfinder", "a.example.com\nb.example.com\nexample.com\n")
    fakebins.add("findomain", "c.example.com\n")
    assert await collect(AssetFinder(), ctx) == ["a.example.com", "b.example.com", "example.com"]
    assert await collect(Findomain(), ctx) == ["c.example.com"]


async def test_gau_and_waybackurls_extract_hosts(ctx, fakebins) -> None:
    fakebins.add(
        "gau", "https://a.example.com/path?x=1\nhttp://b.example.com:8080/\nhttps://other.org/\n"
    )
    assert await collect(Gau(), ctx) == ["a.example.com", "b.example.com"]
    fakebins.add("waybackurls", "https://{STDIN}/\nhttps://w.{STDIN}/x\n", read_stdin=True)
    assert await collect(WaybackUrls(), ctx) == ["example.com", "w.example.com"]


async def test_keyed_binaries_skip_without_key(ctx, fakebins) -> None:
    fakebins.add("chaos", "k.example.com\n")
    fakebins.add("shosubgo", "s.example.com\n")
    fakebins.add("github-subdomains", "g.example.com\n")
    ctx.keys = type(ctx.keys)({})
    stats = {
        s.source: s for s in await run_plugins([ChaosBin(), Shosubgo(), GithubSubdomains()], ctx, T)
    }
    assert all(s.status is SourceStatus.SKIPPED for s in stats.values())
    ctx.keys = type(ctx.keys)({"chaos": ["ck"], "shodan": ["sk"], "github": ["t1", "t2"]})
    stats = {
        s.source: s for s in await run_plugins([ChaosBin(), Shosubgo(), GithubSubdomains()], ctx, T)
    }
    assert all(s.status is SourceStatus.DONE for s in stats.values()), stats
    assert ctx.store.hostnames() == ["g.example.com", "k.example.com", "s.example.com"]
    assert (ctx.tmpdir / ".github_tokens").read_text().split() == ["t1", "t2"]


async def test_haktrails_check(ctx, fakebins, monkeypatch, tmp_path) -> None:
    fakebins.add("haktrails", "h.example.com\n", read_stdin=True)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    ctx.keys = type(ctx.keys)({})
    assert "haktrails config missing" in (Haktrails().check(ctx) or "")
    ctx.keys = type(ctx.keys)({"securitytrails": ["stkey"]})
    assert Haktrails().check(ctx) is None
    assert await collect(Haktrails(), ctx) == ["h.example.com"]
    assert (tmp_path / "home" / ".config" / "haktools" / "haktrails-config.yml").is_file()


async def test_nonzero_exit_keeps_partial_results(ctx, fakebins) -> None:
    fakebins.add("assetfinder", "a.example.com\n", exit_code=1)
    stats = await run_plugins([AssetFinder()], ctx, T)
    assert stats[0].status is SourceStatus.DONE and stats[0].found == 1
    fakebins.add("findomain", "", exit_code=2)
    stats = await run_plugins([Findomain()], ctx, T)
    assert stats[0].status is SourceStatus.ERROR and "exited with 2" in (stats[0].error or "")


async def test_timeout_marks_timeout(ctx, fakebins) -> None:
    fakebins.add("assetfinder", "a.example.com\nb.example.com\nc.example.com\n", delay=3)
    ctx.options.timeout_per_source = 1
    ctx.config.sources.timeouts["assetfinder"] = 1
    stats = await run_plugins([AssetFinder()], ctx, T)
    assert stats[0].status is SourceStatus.TIMEOUT
    assert stats[0].found >= 1


async def test_cero_feeds_resolved_hosts(ctx, fakebins) -> None:
    ctx.store.add_finding(Finding("web.example.com", "x"), root="example.com")
    ctx.store.update_resolution(Resolution("web.example.com", a=["5.6.7.8"]))
    exe = fakebins.add("cero", "san1.example.com\nsan2.example.com\n", read_stdin=True)
    assert exe.exists()
    assert await collect(Cero(), ctx) == ["san1.example.com", "san2.example.com"]
