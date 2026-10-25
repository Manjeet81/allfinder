"""respx-mocked tests for keyed passive plugins, key rotation and provider config."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from allfinder.core.config import KeyRing
from allfinder.core.models import SourceStatus, Target
from allfinder.core.providers import subfinder_provider_mapping, write_subfinder_provider_config
from allfinder.core.runner import run_plugins
from allfinder.plugins.passive.binaryedge import BinaryEdge
from allfinder.plugins.passive.censys import Censys
from allfinder.plugins.passive.fofa import Fofa
from allfinder.plugins.passive.fullhunt import (
    C99,
    BeVigil,
    Chaos,
    FullHunt,
    LeakIX,
    ThreatBook,
    WhoisXml,
)
from allfinder.plugins.passive.github import GithubCode, GrepApp
from allfinder.plugins.passive.hunter import HunterHow
from allfinder.plugins.passive.netlas import Netlas
from allfinder.plugins.passive.passivetotal import (
    CriminalIp,
    DnsDb,
    DnsDumpster,
    PassiveTotal,
    RedHunt,
)
from allfinder.plugins.passive.quake import Quake
from allfinder.plugins.passive.searchengines import Bing, DuckDuckGo
from allfinder.plugins.passive.securitytrails import SecurityTrails
from allfinder.plugins.passive.shodan import Shodan
from allfinder.plugins.passive.virustotal import VirusTotal
from allfinder.plugins.passive.zoomeye import ZoomEye

T = Target("example.com")
ALL_KEYS = {
    "virustotal": ["vt-key-000001"],
    "securitytrails": ["st-key-000001"],
    "shodan": ["sh-key-000001"],
    "censys": ["cid000001:csecret0001"],
    "fofa": ["me@x.com:fofa-key-0001"],
    "zoomeye": ["ze-key-000001"],
    "netlas": ["nl-key-000001"],
    "hunter": ["hu-key-000001"],
    "quake": ["qk-key-000001"],
    "binaryedge": ["be-key-000001"],
    "fullhunt": ["fh-key-000001"],
    "leakix": ["lx-key-000001"],
    "bevigil": ["bv-key-000001"],
    "chaos": ["ch-key-000001"],
    "whoisxml": ["wx-key-000001"],
    "c99": ["c99-key-00001"],
    "threatbook": ["tb-key-000001"],
    "passivetotal": ["user@x.com:pt-key-0001"],
    "dnsdb": ["db-key-000001"],
    "redhunt": ["rh-key-000001"],
    "criminalip": ["ci-key-000001"],
    "dnsdumpster": ["dd-key-000001"],
    "github": ["ghp_token000001"],
}


@pytest.fixture
def kctx(ctx):
    ctx.keys = KeyRing(ALL_KEYS)
    return ctx


async def collect(plugin, ctx) -> list[str]:
    return sorted({f.hostname async for f in plugin.run(ctx, T)})


async def test_all_keyed_skip_without_keys(ctx) -> None:
    ctx.keys = KeyRing({})
    plugins = [
        VirusTotal(),
        SecurityTrails(),
        Shodan(),
        Censys(),
        Fofa(),
        ZoomEye(),
        Netlas(),
        HunterHow(),
        Quake(),
        BinaryEdge(),
        FullHunt(),
        LeakIX(),
        BeVigil(),
        Chaos(),
        WhoisXml(),
        C99(),
        ThreatBook(),
        PassiveTotal(),
        DnsDb(),
        RedHunt(),
        CriminalIp(),
        DnsDumpster(),
        GithubCode(),
    ]
    stats = await run_plugins(plugins, ctx, T)
    assert all(s.status is SourceStatus.SKIPPED for s in stats), [
        (s.source, s.status) for s in stats
    ]


@respx.mock
async def test_virustotal_pagination(kctx) -> None:
    r = respx.get("https://www.virustotal.com/api/v3/domains/example.com/subdomains").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "a.example.com",
                            "attributes": {"last_dns_records": [{"type": "A", "value": "1.1.1.1"}]},
                        }
                    ],
                    "links": {
                        "next": "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=abc"
                    },
                },
            ),
            httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "b.example.com",
                            "attributes": {
                                "last_dns_records": [{"type": "CNAME", "value": "x.example.net"}]
                            },
                        }
                    ],
                    "links": {},
                },
            ),
        ]
    )
    found = [f async for f in VirusTotal().run(kctx, T)]
    assert sorted(f.hostname for f in found) == ["a.example.com", "b.example.com"]
    assert found[0].ips == ["1.1.1.1"] and found[1].cname == "x.example.net"
    assert r.calls[0].request.headers["x-apikey"] == "vt-key-000001"
    assert "cursor=abc" in str(r.calls[1].request.url)


@respx.mock
async def test_securitytrails_and_chaos_prefixes(kctx) -> None:
    respx.get("https://api.securitytrails.com/v1/domain/example.com/subdomains").mock(
        return_value=httpx.Response(200, json={"subdomains": ["www", "dev.api"]})
    )
    assert await collect(SecurityTrails(), kctx) == ["dev.api.example.com", "www.example.com"]
    respx.get("https://dns.projectdiscovery.io/dns/example.com/subdomains").mock(
        return_value=httpx.Response(200, json={"subdomains": ["mail", "*"]})
    )
    assert await collect(Chaos(), kctx) == ["example.com", "mail.example.com"]


@respx.mock
async def test_shodan_pages_and_records(kctx) -> None:
    r = respx.get("https://api.shodan.io/dns/domain/example.com").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "subdomains": ["a", "b"],
                    "data": [
                        {"subdomain": "a", "type": "A", "value": "1.1.1.1"},
                        {"subdomain": "", "type": "A", "value": "2.2.2.2"},
                    ],
                    "more": True,
                },
            ),
            httpx.Response(
                200,
                json={
                    "subdomains": ["c"],
                    "data": [{"subdomain": "c", "type": "CNAME", "value": "cdn.net"}],
                    "more": False,
                },
            ),
        ]
    )
    found = {f.hostname: f async for f in Shodan().run(kctx, T)}
    assert sorted(found) == ["a.example.com", "b.example.com", "c.example.com", "example.com"]
    assert found["a.example.com"].ips == ["1.1.1.1"] and found["c.example.com"].cname == "cdn.net"
    assert "key=sh-key-000001" in str(r.calls[0].request.url)


@respx.mock
async def test_censys_basic_auth_and_cursor(kctx) -> None:
    certs = respx.get("https://search.censys.io/api/v2/certificates/search").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "result": {
                        "hits": [{"names": ["a.example.com", "*.b.example.com"]}],
                        "links": {"next": "cur1"},
                    }
                },
            ),
            httpx.Response(200, json={"result": {"hits": [], "links": {"next": ""}}}),
        ]
    )
    respx.get("https://search.censys.io/api/v2/hosts/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "hits": [
                        {
                            "name": "h.example.com",
                            "services": [
                                {
                                    "tls": {
                                        "certificates": {"leaf_data": {"names": ["i.example.com"]}}
                                    }
                                }
                            ],
                        }
                    ],
                    "links": {"next": ""},
                }
            },
        )
    )
    assert await collect(Censys(), kctx) == [
        "a.example.com",
        "b.example.com",
        "h.example.com",
        "i.example.com",
    ]
    assert certs.calls[0].request.headers["Authorization"].startswith("Basic ")
    assert "cursor=cur1" in str(certs.calls[1].request.url)


@respx.mock
async def test_fofa_zoomeye_netlas_hunter_quake_binaryedge(kctx) -> None:
    respx.get("https://fofa.info/api/v1/search/all").mock(
        return_value=httpx.Response(
            200,
            json={
                "error": False,
                "size": 2,
                "results": [["https://a.example.com:8443", "1.1.1.1"], ["b.example.com", ""]],
            },
        )
    )
    assert await collect(Fofa(), kctx) == ["a.example.com", "b.example.com"]
    respx.get("https://api.zoomeye.org/domain/search").mock(
        return_value=httpx.Response(
            200, json={"total": 1, "list": [{"name": "z.example.com", "ip": ["3.3.3.3"]}]}
        )
    )
    assert await collect(ZoomEye(), kctx) == ["z.example.com"]
    respx.get("https://app.netlas.io/api/domains/").mock(
        return_value=httpx.Response(
            200,
            json={"items": [{"data": {"domain": "n.example.com", "a": ["4.4.4.4"], "cname": []}}]},
        )
    )
    assert await collect(Netlas(), kctx) == ["n.example.com"]
    respx.get("https://api.hunter.how/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "code": 200,
                "data": {"total": 1, "list": [{"domain": "h.example.com", "ip": "5.5.5.5"}]},
            },
        )
    )
    assert await collect(HunterHow(), kctx) == ["h.example.com"]
    respx.post("https://quake.360.net/api/v3/search/quake_service").mock(
        return_value=httpx.Response(
            200,
            json={
                "code": 0,
                "data": [{"ip": "6.6.6.6", "service": {"http": {"host": "q.example.com"}}}],
                "meta": {"pagination": {"total": 1}},
            },
        )
    )
    assert await collect(Quake(), kctx) == ["q.example.com"]
    respx.get("https://api.binaryedge.io/v2/query/domains/subdomain/example.com").mock(
        return_value=httpx.Response(
            200, json={"page": 1, "pagesize": 100, "total": 1, "events": ["be.example.com"]}
        )
    )
    assert await collect(BinaryEdge(), kctx) == ["be.example.com"]


@respx.mock
async def test_single_call_keyed_plugins(kctx) -> None:
    respx.get("https://fullhunt.io/api/v1/domain/example.com/subdomains").mock(
        return_value=httpx.Response(200, json={"hosts": ["f.example.com"]})
    )
    respx.get("https://leakix.net/api/subdomains/example.com").mock(
        return_value=httpx.Response(200, json=[{"subdomain": "l.example.com"}])
    )
    respx.get("https://osint.bevigil.com/api/example.com/subdomains/").mock(
        return_value=httpx.Response(200, json={"subdomains": ["bv.example.com"]})
    )
    respx.get("https://subdomains.whoisxmlapi.com/api/v1").mock(
        return_value=httpx.Response(
            200, json={"result": {"records": [{"domain": "w.example.com"}]}}
        )
    )
    respx.get("https://api.c99.nl/subdomainfinder").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "subdomains": [{"subdomain": "c.example.com", "ip": "7.7.7.7"}]},
        )
    )
    respx.get("https://api.threatbook.cn/v3/domain/sub_domains").mock(
        return_value=httpx.Response(
            200,
            json={
                "response_code": 0,
                "data": {"sub_domains": {"total": 1, "data": ["t.example.com"]}},
            },
        )
    )
    respx.get("https://api.riskiq.net/pt/v2/enrichment/subdomains").mock(
        return_value=httpx.Response(200, json={"subdomains": ["pt"]})
    )
    respx.get("https://reconapi.redhuntlabs.com/community/v1/domains/subdomains").mock(
        return_value=httpx.Response(
            200, json={"subdomains": ["r.example.com"], "metadata": {"result_count": 1}}
        )
    )
    respx.get("https://api.criminalip.io/v1/domain/reports").mock(
        return_value=httpx.Response(
            200, json={"status": 200, "data": {"reports": [{"domain": "ci.example.com"}]}}
        )
    )
    assert await collect(FullHunt(), kctx) == ["f.example.com"]
    assert await collect(LeakIX(), kctx) == ["l.example.com"]
    assert await collect(BeVigil(), kctx) == ["bv.example.com"]
    assert await collect(WhoisXml(), kctx) == ["w.example.com"]
    assert await collect(C99(), kctx) == ["c.example.com"]
    assert await collect(ThreatBook(), kctx) == ["t.example.com"]
    assert await collect(PassiveTotal(), kctx) == ["pt.example.com"]
    assert await collect(RedHunt(), kctx) == ["r.example.com"]
    assert await collect(CriminalIp(), kctx) == ["ci.example.com"]


@respx.mock
async def test_dnsdb_ndjson_and_dnsdumpster(kctx) -> None:
    nd = "\n".join(
        [
            json.dumps({"cond": "begin"}),
            json.dumps({"obj": {"rrname": "a.example.com.", "rrtype": "A", "rdata": ["1.1.1.1"]}}),
            json.dumps(
                {
                    "obj": {
                        "rrname": "b.example.com.",
                        "rrtype": "CNAME",
                        "rdata": ["c.example.net."],
                    }
                }
            ),
            json.dumps({"cond": "succeeded"}),
        ]
    )
    respx.get("https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.example.com").mock(
        return_value=httpx.Response(200, text=nd)
    )
    found = {f.hostname: f async for f in DnsDb().run(kctx, T)}
    assert sorted(found) == ["a.example.com", "b.example.com"]
    assert found["b.example.com"].cname == "c.example.net"
    respx.get("https://api.dnsdumpster.com/domain/example.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "a": [{"host": "d.example.com", "ips": [{"ip": "9.9.9.9"}]}],
                "cname": [{"host": "e.example.com", "target": "x.net"}],
                "mx": [],
                "ns": [{"host": "ns1.example.com", "ips": []}],
                "total_a_recs": 1,
            },
        )
    )
    assert await collect(DnsDumpster(), kctx) == [
        "d.example.com",
        "e.example.com",
        "ns1.example.com",
    ]


@respx.mock
async def test_github_and_grepapp(kctx) -> None:
    respx.get("https://api.github.com/search/code").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "html_url": "https://github.com/x/y/blob/main/a.js",
                        "text_matches": [{"fragment": "fetch('https://api.example.com/v1')"}],
                    }
                ]
            },
        )
    )
    assert await collect(GithubCode(), kctx) == ["api.example.com"]
    respx.get("https://grep.app/api/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "content": {
                                "snippet": "<mark>cdn</mark>.example.com &amp; mail.example.com"
                            }
                        }
                    ]
                }
            },
        )
    )
    assert await collect(GrepApp(), kctx) == ["cdn.example.com", "mail.example.com"]


@respx.mock
async def test_key_rotation_on_403(kctx) -> None:
    kctx.keys = KeyRing({"securitytrails": ["bad-key-000001", "good-key-00001"]})
    r = respx.get("https://api.securitytrails.com/v1/domain/example.com/subdomains").mock(
        side_effect=lambda req: (
            httpx.Response(403)
            if req.headers["APIKEY"].startswith("bad")
            else httpx.Response(200, json={"subdomains": ["ok"]})
        )
    )
    assert await collect(SecurityTrails(), kctx) == ["ok.example.com"]
    assert r.call_count == 2
    assert kctx.keys.usable("securitytrails") == 1
    # all keys bad -> AuthError captured as source error with redacted message
    kctx.keys = KeyRing({"securitytrails": ["bad-key-000001"]})
    stats = await run_plugins([SecurityTrails()], kctx, T)
    assert stats[0].status is SourceStatus.ERROR and "403" in (stats[0].error or "")
    assert "bad-key" not in (stats[0].error or "")


@respx.mock
async def test_search_engines(ctx) -> None:
    page = '<a href="https://www.example.com/x">w</a> <cite>mail.example.com</cite>'
    empty = "<html>no results</html>"
    r = respx.get("https://www.bing.com/search").mock(
        side_effect=[
            httpx.Response(200, text=page),
            httpx.Response(200, text=empty),
            httpx.Response(200, text=empty),
        ]
    )
    assert await collect(Bing(), ctx) == ["mail.example.com", "www.example.com"]
    assert "-site" in str(r.calls[-1].request.url) or r.call_count >= 2
    respx.get("https://html.duckduckgo.com/html/").mock(
        return_value=httpx.Response(200, text="Please complete the CAPTCHA")
    )
    assert await collect(DuckDuckGo(), ctx) == []
    respx.get("https://html.duckduckgo.com/html/").mock(return_value=httpx.Response(429))
    assert await collect(DuckDuckGo(), ctx) == []


def test_provider_mapping_and_file(ctx) -> None:
    mapping = subfinder_provider_mapping(
        {"shodan": ["a"], "whoisxml": ["b"], "unknown": ["c"], "zoomeye": []}
    )
    assert mapping == {"shodan": ["a"], "whoisxmlapi": ["b"]}
    ctx.keys = KeyRing({})
    assert write_subfinder_provider_config(ctx) is None
    ctx.keys = KeyRing({"shodan": ["sh-key-000001"], "censys": ["id:secret"]})
    path = write_subfinder_provider_config(ctx)
    assert path is not None and path.is_file()
    text = path.read_text()
    assert "shodan:" in text and "sh-key-000001" in text and "censys:" in text
    assert write_subfinder_provider_config(ctx) == path  # unchanged, not rewritten


def test_searchengines_excluded_by_default(fake_registry) -> None:
    from allfinder.core.config import Config
    from allfinder.core.context import RunOptions
    from allfinder.core.pipeline import Pipeline

    class Dummy:
        pass

    opts = RunOptions()
    dummy = Dummy()
    dummy.options = opts  # type: ignore[attr-defined]
    dummy.config = Config()  # type: ignore[attr-defined]
    dummy.scope = type("S", (), {"roots": ("example.com",)})()  # type: ignore[attr-defined]
    p = Pipeline.__new__(Pipeline)
    p.ctx = dummy  # type: ignore[assignment]
    p.registry = fake_registry
    from allfinder.core.models import SourceKind

    names = {pl.name for pl in p.select(SourceKind.PASSIVE)}
    assert "bing" not in names and "crtsh" in names
    opts.search_engines = True
    assert "bing" in {pl.name for pl in p.select(SourceKind.PASSIVE)}
    opts.search_engines = False
    opts.use = ["bing"]
    assert {pl.name for pl in p.select(SourceKind.PASSIVE)} == {"bing"}
