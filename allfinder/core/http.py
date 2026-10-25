"""Shared async HTTP client, per-host token-bucket rate limiter and retrying fetch."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

import httpx

from allfinder.core.config import HttpConfig

log = logging.getLogger("allfinder.http")

RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524})
MAX_RETRY_AFTER = 30.0


class HttpError(Exception):
    def __init__(self, message: str, *, status: int | None = None, url: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.url = url


class RateLimited(HttpError):
    """Final 429 after retries (callers may rotate the API key)."""


class AuthError(HttpError):
    """401 / 403: key missing, wrong or exhausted."""


class _Bucket:
    __slots__ = ("rate", "tokens", "updated", "lock")

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self.tokens = 1.0  # first request is immediate, then steady spacing
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(
                    max(self.rate, 1.0), self.tokens + (now - self.updated) * self.rate
                )
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


class RateLimiter:
    """Token buckets keyed by an arbitrary string (usually the API host)."""

    def __init__(self, *, enabled: bool = True) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self.enabled = enabled

    async def acquire(self, key: str, rate: float | None) -> None:
        if not self.enabled or not rate or rate <= 0:
            return
        bucket = self._buckets.get(key)
        if bucket is None or bucket.rate != rate:
            bucket = self._buckets[key] = _Bucket(rate)
        await bucket.acquire()


def _http2_available() -> bool:
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


def make_client(cfg: HttpConfig | None = None, **overrides: Any) -> httpx.AsyncClient:
    cfg = cfg or HttpConfig()
    kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(cfg.timeout, connect=min(10.0, cfg.timeout)),
        "follow_redirects": True,
        "headers": {"User-Agent": cfg.user_agent, "Accept": "*/*"},
        "verify": cfg.verify_tls,
        "http2": _http2_available(),
        "limits": httpx.Limits(max_connections=100, max_keepalive_connections=20),
    }
    if cfg.proxy:
        kwargs["proxy"] = cfg.proxy
    kwargs.update(overrides)
    return httpx.AsyncClient(**kwargs)


def host_of(url: str) -> str:
    return urlsplit(url).hostname or url


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if not value:
        return None
    try:
        return min(float(value), MAX_RETRY_AFTER)
    except ValueError:
        return None


async def fetch(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 2,
    limiter: RateLimiter | None = None,
    rate: float | None = None,
    rate_key: str | None = None,
    ok: Iterable[int] | None = None,
    raise_for_status: bool = True,
    backoff: float = 1.0,
    **kwargs: Any,
) -> httpx.Response:
    """Perform a request with rate limiting and retries on transport errors / 429 / 5xx.

    ``ok`` lists statuses that are returned as-is without raising (e.g. 404
    for "no results").  After the last attempt a 429 raises :class:`RateLimited`,
    401/403 raise :class:`AuthError`, other >= 400 raise :class:`HttpError`.
    """
    ok_set = set(ok or ())
    attempt = 0
    last_exc: Exception | None = None
    while True:
        if limiter is not None:
            await limiter.acquire(rate_key or host_of(url), rate)
        try:
            resp = await client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt >= retries:
                raise HttpError(f"{type(exc).__name__}: {exc}", url=url) from exc
            await asyncio.sleep(_sleep_for(attempt, backoff))
            attempt += 1
            continue

        status = resp.status_code
        if status < 400 or status in ok_set or not raise_for_status:
            return resp
        if status in RETRY_STATUSES and attempt < retries:
            delay = _retry_after(resp) or _sleep_for(attempt, backoff)
            log.debug("%s %s -> %s, retrying in %.1fs", method, url, status, delay)
            await resp.aclose()
            await asyncio.sleep(delay)
            attempt += 1
            continue
        body = resp.text[:200].replace("\n", " ") if resp.content else ""
        msg = f"HTTP {status} for {url}" + (f": {body}" if body else "")
        if status == 429:
            raise RateLimited(msg, status=status, url=url)
        if status in (401, 403):
            raise AuthError(msg, status=status, url=url)
        raise HttpError(msg, status=status, url=url)
    raise HttpError(str(last_exc), url=url)  # pragma: no cover - unreachable


def _sleep_for(attempt: int, backoff: float) -> float:
    return float(backoff * (2**attempt) + random.uniform(0, 0.5))


async def get_json(client: httpx.AsyncClient, url: str, **kwargs: Any) -> Any:
    resp = await fetch(client, "GET", url, **kwargs)
    try:
        return resp.json()
    except ValueError as exc:
        raise HttpError(
            f"invalid JSON from {url}: {exc}", status=resp.status_code, url=url
        ) from exc
