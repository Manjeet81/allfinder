import asyncio
import time

import httpx
import pytest
import respx

from allfinder.core.config import HttpConfig
from allfinder.core.http import (
    AuthError,
    HttpError,
    RateLimited,
    RateLimiter,
    fetch,
    get_json,
    make_client,
)


@pytest.fixture
async def client():
    async with make_client(HttpConfig(timeout=5)) as c:
        yield c


@respx.mock
async def test_fetch_ok_and_json(client: httpx.AsyncClient) -> None:
    respx.get("https://api.test/x").mock(return_value=httpx.Response(200, json={"a": 1}))
    assert await get_json(client, "https://api.test/x") == {"a": 1}


@respx.mock
async def test_fetch_retries_on_5xx_then_ok(client: httpx.AsyncClient) -> None:
    route = respx.get("https://api.test/r").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, text="ok")]
    )
    resp = await fetch(client, "GET", "https://api.test/r", retries=2, backoff=0.01)
    assert resp.text == "ok"
    assert route.call_count == 2


@respx.mock
async def test_fetch_transport_error_retry(client: httpx.AsyncClient) -> None:
    route = respx.get("https://api.test/t").mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(200, text="ok")]
    )
    resp = await fetch(client, "GET", "https://api.test/t", retries=1, backoff=0.01)
    assert resp.text == "ok" and route.call_count == 2


@respx.mock
async def test_fetch_errors(client: httpx.AsyncClient) -> None:
    respx.get("https://api.test/429").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"})
    )
    respx.get("https://api.test/403").mock(return_value=httpx.Response(403, text="nope"))
    respx.get("https://api.test/500").mock(return_value=httpx.Response(500))
    respx.get("https://api.test/404").mock(return_value=httpx.Response(404))
    respx.get("https://api.test/conn").mock(side_effect=httpx.ConnectError("x"))
    with pytest.raises(RateLimited):
        await fetch(client, "GET", "https://api.test/429", retries=1, backoff=0.01)
    with pytest.raises(AuthError) as ei:
        await fetch(client, "GET", "https://api.test/403", retries=0)
    assert ei.value.status == 403
    with pytest.raises(HttpError):
        await fetch(client, "GET", "https://api.test/500", retries=0)
    with pytest.raises(HttpError):
        await fetch(client, "GET", "https://api.test/conn", retries=0)
    # ok= lets a status through
    resp = await fetch(client, "GET", "https://api.test/404", ok=[404])
    assert resp.status_code == 404
    resp = await fetch(client, "GET", "https://api.test/500", retries=0, raise_for_status=False)
    assert resp.status_code == 500


@respx.mock
async def test_get_json_invalid(client: httpx.AsyncClient) -> None:
    respx.get("https://api.test/bad").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(HttpError):
        await get_json(client, "https://api.test/bad")


async def test_rate_limiter_spacing() -> None:
    lim = RateLimiter()
    t0 = time.monotonic()
    for _ in range(4):
        await lim.acquire("k", 20)  # 20/s -> 3 waits of 50ms after the first
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.10
    # no rate -> no waiting
    t1 = time.monotonic()
    for _ in range(50):
        await lim.acquire("free", None)
    assert time.monotonic() - t1 < 0.05


async def test_rate_limiter_concurrent() -> None:
    lim = RateLimiter()
    t0 = time.monotonic()
    await asyncio.gather(*(lim.acquire("c", 10) for _ in range(5)))
    assert time.monotonic() - t0 >= 0.3
