import httpx
import respx

from allfinder.core.models import SourceStatus, Target
from allfinder.core.runner import run_plugins
from allfinder.plugins.passive.crtsh import CrtSh

ROWS = [
    {"name_value": "*.example.com\nwww.example.com", "common_name": "www.example.com"},
    {"name_value": "API.Example.com", "common_name": "api.example.com"},
    {"name_value": "mail.example.com\nmail.example.com", "common_name": "other.net"},
    {"name_value": "example.com", "common_name": "example.com"},
    "garbage",
]


@respx.mock
async def test_crtsh_parses_and_dedups(ctx) -> None:
    route = respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=ROWS))
    found = [f async for f in CrtSh().run(ctx, Target("example.com"))]
    hosts = sorted(f.hostname for f in found)
    assert hosts == [
        "api.example.com",
        "example.com",
        "mail.example.com",
        "other.net",
        "www.example.com",
    ]
    assert all(f.source == "crtsh" for f in found)
    # the apex was already seen in the wildcard query -> second query skipped
    assert route.call_count == 1


@respx.mock
async def test_crtsh_second_query_when_no_apex(ctx) -> None:
    route = respx.get("https://crt.sh/").mock(
        side_effect=[
            httpx.Response(200, json=[{"name_value": "a.example.com"}]),
            httpx.Response(200, json=[{"name_value": "example.com"}]),
        ]
    )
    found = sorted([f.hostname async for f in CrtSh().run(ctx, Target("example.com"))])
    assert found == ["a.example.com", "example.com"]
    assert route.call_count == 2


@respx.mock
async def test_crtsh_404_and_error(ctx) -> None:
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(404))
    assert [f async for f in CrtSh().run(ctx, Target("example.com"))] == []
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(502, text="bad gateway"))
    stats = await run_plugins([CrtSh()], ctx, Target("example.com"))
    assert stats[0].status is SourceStatus.ERROR
    assert "502" in (stats[0].error or "")
