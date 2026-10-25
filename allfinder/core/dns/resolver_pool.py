"""Resolver pool + native async resolver (aiodns/pycares) with QPS limiting.

Used for wildcard probing, passive-result resolution, the brute-force
fallback when massdns/puredns are unavailable (Windows), and record mining.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import random
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

from allfinder.core.models import Resolution
from allfinder.core.normalize import normalize_hostname

log = logging.getLogger("allfinder.dns")

try:
    import aiodns
    import pycares

    HAVE_AIODNS = True
except ImportError:  # pragma: no cover - aiodns is a hard dependency
    aiodns = None  # type: ignore[assignment]
    pycares = None  # type: ignore[assignment]
    HAVE_AIODNS = False

# c-ares error codes
E_NODATA = 1
E_SERVFAIL = 3
E_NOTFOUND = 4
E_REFUSED = 6
E_BADRESP = 10
E_CONNREFUSED = 11
E_TIMEOUT = 12
_FINAL_NEGATIVE = {E_NODATA, E_NOTFOUND}
_RETRYABLE = {E_SERVFAIL, E_REFUSED, E_BADRESP, E_CONNREFUSED, E_TIMEOUT}

_TYPE_A, _TYPE_NS, _TYPE_CNAME, _TYPE_PTR, _TYPE_MX, _TYPE_TXT, _TYPE_AAAA, _TYPE_SRV = (
    1,
    2,
    5,
    12,
    15,
    16,
    28,
    33,
)


class QpsLimiter:
    """Global token bucket for DNS queries per second."""

    def __init__(self, qps: float) -> None:
        self.qps = max(1.0, float(qps))
        self._tokens = self.qps
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.qps, self._tokens + (now - self._updated) * self.qps)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.qps)


@dataclass(slots=True)
class ResolverStats:
    queries: int = 0
    timeouts: int = 0
    servfail: int = 0
    resolved: int = 0
    bad_resolvers: set[str] = field(default_factory=set)


class ResolverPool:
    """Round-robin over resolver IPs; each query goes to one resolver with retries on others."""

    def __init__(
        self,
        resolvers: Iterable[str],
        *,
        trusted: Iterable[str] | None = None,
        qps: float = 500,
        concurrency: int = 200,
        timeout: float = 3.0,
        retries: int = 2,
        ipv6: bool = False,
    ) -> None:
        self.resolvers = [r for r in dict.fromkeys(resolvers) if r]
        if not self.resolvers:
            raise ValueError("resolver pool needs at least one resolver")
        self.trusted = [r for r in dict.fromkeys(trusted or []) if r] or self.resolvers[:4]
        self.qps = QpsLimiter(qps)
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.timeout = timeout
        self.retries = retries
        self.ipv6 = ipv6
        self.stats = ResolverStats()
        self._cycle = itertools.cycle(self.resolvers)
        self._channels: dict[str, aiodns.DNSResolver] = {}
        self._failures: dict[str, int] = {}

    # ------------------------------------------------------------------ channels
    def _channel(self, ip: str) -> aiodns.DNSResolver:
        ch = self._channels.get(ip)
        if ch is None:
            ch = self._channels[ip] = aiodns.DNSResolver(
                nameservers=[ip], timeout=self.timeout, tries=1, rotate=False
            )
        return ch

    def _pick(self, trusted: bool = False) -> str:
        pool = self.trusted if trusted else self.resolvers
        for _ in range(len(pool)):
            ip = next(self._cycle) if not trusted else random.choice(pool)
            if ip in pool and self._failures.get(ip, 0) < 50:
                return ip
        return random.choice(pool)

    def _mark_failure(self, ip: str) -> None:
        n = self._failures.get(ip, 0) + 1
        self._failures[ip] = n
        if n == 50:
            self.stats.bad_resolvers.add(ip)
            log.debug("resolver %s disabled after repeated failures", ip)

    def close(self) -> None:
        for ch in self._channels.values():
            with contextlib.suppress(Exception):
                ch.cancel()
        self._channels.clear()

    # ------------------------------------------------------------------ queries
    async def query_raw(
        self, name: str, qtype: str, *, trusted: bool = False
    ) -> list[tuple[int, str, str]]:
        """Return ``[(rtype, owner, data), ...]`` for *name*; ``[]`` on NXDOMAIN/NODATA.

        Raises ``TimeoutError`` after all retries failed with retryable errors.
        """
        last_code = E_TIMEOUT
        for attempt in range(self.retries + 1):
            ip = self._pick(trusted=trusted or attempt == self.retries)
            await self.qps.acquire()
            async with self.sem:
                self.stats.queries += 1
                try:
                    result = await self._channel(ip).query_dns(name, qtype)
                except aiodns.error.DNSError as exc:
                    code = exc.args[0] if exc.args else E_TIMEOUT
                    if code in _FINAL_NEGATIVE:
                        return []
                    last_code = code
                    if code == E_TIMEOUT:
                        self.stats.timeouts += 1
                    elif code == E_SERVFAIL:
                        self.stats.servfail += 1
                    self._mark_failure(ip)
                    continue
                except (asyncio.CancelledError, KeyboardInterrupt):
                    raise
                except Exception as exc:  # pragma: no cover - c-ares oddities
                    log.debug("query %s %s via %s failed: %s", name, qtype, ip, exc)
                    self._mark_failure(ip)
                    continue
            out: list[tuple[int, str, str]] = []
            for rec in getattr(result, "answer", None) or []:
                data = _record_data(rec)
                if data:
                    out.append((int(rec.type), str(rec.name).lower(), data))
            return out
        raise TimeoutError(f"{name}/{qtype}: resolvers failed (last code {last_code})")

    async def resolve(self, host: str) -> Resolution:
        """A (+ CNAME chain) and, when nothing came back, AAAA.  Never raises."""
        res = Resolution(host)
        try:
            records = await self.query_raw(host, "A")
        except TimeoutError as exc:
            res.error = str(exc)
            return res
        _apply(res, records)
        if (self.ipv6 or not res.resolved) and not res.error:
            with contextlib.suppress(TimeoutError):
                _apply(res, await self.query_raw(host, "AAAA"))
        if res.resolved:
            self.stats.resolved += 1
        return res

    async def resolve_trusted(self, host: str) -> Resolution:
        """Re-validate with trusted resolvers (used for brute-force hits)."""
        res = Resolution(host)
        try:
            _apply(res, await self.query_raw(host, "A", trusted=True))
        except TimeoutError as exc:
            res.error = str(exc)
        return res

    async def records(self, host: str, qtype: str) -> list[str]:
        """Record data strings for *host*/*qtype* (NS, MX, TXT, SRV, PTR, ...)."""
        try:
            return [data for _, _, data in await self.query_raw(host, qtype)]
        except TimeoutError:
            return []

    async def resolve_many(
        self,
        hosts: Iterable[str],
        *,
        on_result: Callable[[Resolution], Awaitable[None] | None] | None = None,
        cancel: asyncio.Event | None = None,
    ) -> dict[str, Resolution]:
        """Resolve *hosts* concurrently; returns hostname -> Resolution."""
        out: dict[str, Resolution] = {}

        async def one(h: str) -> None:
            if cancel is not None and cancel.is_set():
                return
            res = await self.resolve(h)
            out[h] = res
            if on_result is not None:
                r = on_result(res)
                if asyncio.iscoroutine(r):
                    await r

        async with asyncio.TaskGroup() as tg:
            for h in hosts:
                tg.create_task(one(h))
        return out


def _record_data(rec: object) -> str:
    data = getattr(rec, "data", None)
    for attr in ("addr", "cname", "nsdname", "ptrdname", "exchange", "host", "target"):
        v = getattr(data, attr, None)
        if v:
            return str(v)
    txt = getattr(data, "txt", None)
    if txt is not None:
        if isinstance(txt, bytes):
            return txt.decode("utf-8", "replace")
        if isinstance(txt, list | tuple):
            return "".join(
                t.decode("utf-8", "replace") if isinstance(t, bytes) else str(t) for t in txt
            )
        return str(txt)
    strings = getattr(data, "strings", None)
    if strings is not None:
        return "".join(
            s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s) for s in strings
        )
    return str(data) if data is not None else ""


def _apply(res: Resolution, records: list[tuple[int, str, str]]) -> None:
    for rtype, _owner, data in records:
        if rtype == _TYPE_A and data not in res.a:
            res.a.append(data)
        elif rtype == _TYPE_AAAA and data not in res.aaaa:
            res.aaaa.append(data)
        elif rtype == _TYPE_CNAME:
            target = normalize_hostname(data)
            if target and target not in res.cname:
                res.cname.append(target)


async def validate_resolvers(
    candidates: Iterable[str],
    *,
    probe: str = "example.com",
    expected_any: bool = True,
    timeout: float = 2.0,
    concurrency: int = 100,
) -> list[str]:
    """Keep resolvers that answer a probe query (and do not hijack NXDOMAIN)."""
    sem = asyncio.Semaphore(concurrency)
    good: list[str] = []
    bogus = f"{random.randbytes(6).hex()}.{probe}"

    async def check(ip: str) -> None:
        async with sem:
            ch = aiodns.DNSResolver(nameservers=[ip], timeout=timeout, tries=1)
            try:
                r = await ch.query_dns(probe, "A")
                if expected_any and not getattr(r, "answer", None):
                    return
                try:
                    await ch.query_dns(bogus, "A")
                    return  # answered a random name -> hijacking resolver
                except aiodns.error.DNSError as exc:
                    if exc.args and exc.args[0] not in _FINAL_NEGATIVE:
                        return
                good.append(ip)
            except Exception:
                return
            finally:
                with contextlib.suppress(Exception):
                    ch.cancel()

    await asyncio.gather(*(check(ip) for ip in dict.fromkeys(candidates)))
    return good
