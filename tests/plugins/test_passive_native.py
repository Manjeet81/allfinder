"""respx-mocked tests for every native passive plugin."""

from __future__ import annotations

import httpx
import pytest
import respx

from allfinder.core.models import SourceStatus, Target
from allfinder.core.runner import run_plugins
from allfinder.plugins.passive.anubis import Anubis
from allfinder.plugins.passive.certspotter import CertSpotter
from allfinder.plugins.passive.columbus import Columbus
from allfinder.plugins.passive.commoncrawl import CommonCrawl
from allfinder.plugins.passive.digitorus import Digitorus
from allfinder.plugins.passive.dnsrepo import DnsRepo
from allfinder.plugins.passive.hackertarget import HackerTarget
from allfinder.plugins.passive.otx import Otx
from allfinder.plugins.passive.rapiddns import RapidDns
from allfinder.plugins.passive.riddler import Riddler
from allfinder.plugins.passive.robtex import Robtex
from allfinder.plugins.passive.shrewdeye import ShrewdEye
from allfinder.plugins.passive.sitedossier import SiteDossier
from allfinder.plugins.passive.subdomaincenter import SubdomainCenter
from allfinder.plugins.passive.threatminer import ThreatMiner
from allfinder.plugins.passive.urlscan import UrlScan
from allfinder.plugins.passive.wayback import Wayback

T = Target("example.com")


async def collect(plugin, ctx) -> list[str]:
    return sorted({f.hostname async for f in plugin.run(ctx, T)})


@respx.mock
async def test_certspotter_pagination_and_key(ctx) -> None:
    ctx.keys = type(ctx.keys)({"certspotter": ["cs-key-123456"]})
    route = respx.get("https://api.certspotter.com/v1/issuances").mock(
        side_effect=[
            httpx.Response(
                200, json=[{"id": "1", "dns_names": ["a.example.com", "*.b.example.com"]}]
            ),
            httpx.Response(200, json=[{"id": "2", "dns_names": ["c.example.com", "other.org"]}]),
            httpx.Response(200, json=[]),
        ]
    )
    assert await collect(CertSpotter(), ctx) == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
        "other.org",
    ]
    assert route.call_count == 3
    assert route.calls[0].request.headers["Authorization"] == "Bearer cs-key-123456"
    assert "after=1" in str(route.calls[1].request.url)


@respx.mock
async def test_otx(ctx) -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns").mock(
        return_value=httpx.Response(
            200,
            json={
                "passive_dns": [
                    {"hostname": "a.example.com", "address": "1.2.3.4", "record_type": "A"},
                    {
                        "hostname": "b.example.com",
                        "address": "cdn.example.net",
                        "record_type": "CNAME",
                    },
                    {"hostname": "a.example.com", "address": "1.2.3.5", "record_type": "A"},
                ]
            },
        )
    )
    url_route = respx.get(
        "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
    ).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "url_list": [{"hostname": "c.example.com", "url": "http://c.example.com/x"}],
                    "has_next": True,
                },
            ),
            httpx.Response(
                200, json={"url_list": [{"url": "https://d.example.com:8443/y"}], "has_next": False}
            ),
        ]
    )
    found = [f async for f in Otx().run(ctx, T)]
    hosts = sorted(f.hostname for f in found)
    assert hosts == ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]
    a = next(f for f in found if f.hostname == "a.example.com")
    assert a.ips == ["1.2.3.4"]
    b = next(f for f in found if f.hostname == "b.example.com")
    assert b.cname == "cdn.example.net"
    assert url_route.call_count == 2


@respx.mock
async def test_hackertarget(ctx) -> None:
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="a.example.com,1.1.1.1\nb.example.com,2.2.2.2\n")
    )
    found = [f async for f in HackerTarget().run(ctx, T)]
    assert [(f.hostname, f.ips) for f in found] == [
        ("a.example.com", ["1.1.1.1"]),
        ("b.example.com", ["2.2.2.2"]),
    ]
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="API count exceeded - Increase Quota with Membership")
    )
    stats = await run_plugins([HackerTarget()], ctx, T)
    assert stats[0].status is SourceStatus.ERROR and "API count" in (stats[0].error or "")


@respx.mock
async def test_rapiddns_paging(ctx) -> None:
    page1 = (
        '<a href="?page=2">2</a><a href="?page=3">3</a><td>a.example.com</td><td>b.example.com</td>'
    )
    page2 = "<td>c.example.com</td>"
    page3 = "<td>c.example.com</td>"
    route = respx.get("https://rapiddns.io/subdomain/example.com").mock(
        side_effect=[
            httpx.Response(200, text=page1),
            httpx.Response(200, text=page2),
            httpx.Response(200, text=page3),
        ]
    )
    assert await collect(RapidDns(), ctx) == ["a.example.com", "b.example.com", "c.example.com"]
    assert route.call_count == 3


@respx.mock
async def test_anubis_subdomaincenter_threatminer_shrewdeye(ctx) -> None:
    respx.get("https://jldc.me/anubis/subdomains/example.com").mock(
        return_value=httpx.Response(200, json=["a.example.com", "x.other.org", 5])
    )
    assert await collect(Anubis(), ctx) == ["a.example.com"]
    respx.get("https://api.subdomain.center/").mock(
        return_value=httpx.Response(200, json=["b.example.com"])
    )
    assert await collect(SubdomainCenter(), ctx) == ["b.example.com"]
    respx.get("https://api.threatminer.org/v2/domain.php").mock(
        return_value=httpx.Response(200, json={"status_code": "200", "results": ["c.example.com"]})
    )
    assert await collect(ThreatMiner(), ctx) == ["c.example.com"]
    respx.get("https://shrewdeye.app/domains/example.com.txt").mock(
        return_value=httpx.Response(200, text="d.example.com\ne.example.com\n")
    )
    assert await collect(ShrewdEye(), ctx) == ["d.example.com", "e.example.com"]
    respx.get("https://shrewdeye.app/domains/example.com.txt").mock(
        return_value=httpx.Response(404)
    )
    assert await collect(ShrewdEye(), ctx) == []


@respx.mock
async def test_columbus_prefixes(ctx) -> None:
    respx.get("https://columbus.elmasy.com/api/lookup/example.com").mock(
        return_value=httpx.Response(200, json=["www", "", "api.v2", "full.example.com", "evil.net"])
    )
    assert await collect(Columbus(), ctx) == [
        "api.v2.example.com",
        "evil.net.example.com",
        "example.com",
        "full.example.com",
        "www.example.com",
    ]


@respx.mock
async def test_wayback_stream(ctx) -> None:
    body = "http://a.example.com/x\nhttps://b.example.com:8080/y?z\nhttp://a.example.com/other\n"
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(200, text=body)
    )
    assert await collect(Wayback(), ctx) == ["a.example.com", "b.example.com"]
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(503, text="busy")
    )
    stats = await run_plugins([Wayback()], ctx, T)
    assert stats[0].status is SourceStatus.ERROR


@respx.mock
async def test_commoncrawl(ctx) -> None:
    respx.get("https://index.commoncrawl.org/collinfo.json").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "CC-MAIN-2026-10",
                    "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-10-index",
                },
                {
                    "id": "CC-MAIN-2026-05",
                    "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-05-index",
                },
            ],
        )
    )
    respx.get("https://index.commoncrawl.org/CC-MAIN-2026-10-index").mock(
        return_value=httpx.Response(
            200,
            text='{"url": "http://a.example.com/"}\n{"url": "http://b.example.com/x"}\nnot json\n',
        )
    )
    respx.get("https://index.commoncrawl.org/CC-MAIN-2026-05-index").mock(
        return_value=httpx.Response(404)
    )
    assert await collect(CommonCrawl(), ctx) == ["a.example.com", "b.example.com"]


@respx.mock
async def test_urlscan_paging(ctx) -> None:
    route = respx.get("https://urlscan.io/api/v1/search/").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "page": {"domain": "a.example.com"},
                            "task": {"url": "https://t.example.com/"},
                            "sort": [1, "x"],
                        }
                    ],
                    "has_more": True,
                },
            ),
            httpx.Response(
                200,
                json={
                    "results": [{"page": {"domain": "b.example.com"}, "sort": [2, "y"]}],
                    "has_more": False,
                },
            ),
        ]
    )
    assert await collect(UrlScan(), ctx) == ["a.example.com", "b.example.com", "t.example.com"]
    assert "search_after=1%2Cx" in str(route.calls[1].request.url) or "search_after=1,x" in str(
        route.calls[1].request.url
    )


@respx.mock
async def test_riddler_skip_on_login(ctx) -> None:
    respx.get("https://riddler.io/search/exportcsv").mock(return_value=httpx.Response(403))
    stats = await run_plugins([Riddler()], ctx, T)
    assert stats[0].status is SourceStatus.SKIPPED
    respx.get("https://riddler.io/search/exportcsv").mock(
        return_value=httpx.Response(200, text="1.1.1.1,a.example.com\n")
    )
    assert await collect(Riddler(), ctx) == ["a.example.com"]


@respx.mock
async def test_robtex_forward_reverse(ctx) -> None:
    respx.get("https://freeapi.robtex.com/pdns/forward/example.com").mock(
        return_value=httpx.Response(
            200,
            text='{"rrname":"example.com","rrdata":"1.2.3.4","rrtype":"A"}\n{"rrname":"example.com","rrdata":"ns1.example.com","rrtype":"NS"}\n',
        )
    )
    respx.get("https://freeapi.robtex.com/pdns/reverse/1.2.3.4").mock(
        return_value=httpx.Response(
            200, text='{"rrname":"www.example.com","rrdata":"1.2.3.4","rrtype":"A"}\nbroken\n'
        )
    )
    found = [f async for f in Robtex().run(ctx, T)]
    assert sorted(f.hostname for f in found) == ["example.com", "www.example.com"]
    assert next(f for f in found if f.hostname == "www.example.com").ips == ["1.2.3.4"]


@respx.mock
async def test_sitedossier_digitorus_dnsrepo(ctx) -> None:
    respx.get("http://www.sitedossier.com/parentdomain/example.com/1").mock(
        return_value=httpx.Response(
            200, text='<a href="/site/a.example.com">a.example.com</a> Show next 100'
        )
    )
    respx.get("http://www.sitedossier.com/parentdomain/example.com/101").mock(
        return_value=httpx.Response(200, text="<p>No data currently available.</p>")
    )
    assert await collect(SiteDossier(), ctx) == ["a.example.com"]
    respx.get("https://certificatedetails.com/example.com").mock(
        return_value=httpx.Response(200, text="<li>b.example.com</li><li>*.c.example.com</li>")
    )
    assert await collect(Digitorus(), ctx) == ["b.example.com", "c.example.com"]
    respx.get("https://dnsrepo.noc.org/").mock(
        return_value=httpx.Response(200, text="<td>d.example.com</td>")
    )
    assert await collect(DnsRepo(), ctx) == ["d.example.com"]


@pytest.mark.parametrize(
    "plugin_cls",
    [Anubis, SubdomainCenter, ThreatMiner, Columbus, Digitorus, CertSpotter, UrlScan, HackerTarget],
)
@respx.mock
async def test_server_error_is_captured(ctx, plugin_cls) -> None:
    respx.route().mock(return_value=httpx.Response(500, text="oops"))
    stats = await run_plugins([plugin_cls()], ctx, T)
    assert stats[0].status is SourceStatus.ERROR
    assert "500" in (stats[0].error or "")
