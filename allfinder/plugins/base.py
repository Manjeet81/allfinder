"""Plugin interface and the two helper base classes (HTTP API, external binary).

A plugin is one source or technique.  It yields :class:`Finding` objects
asynchronously; the runner stores each immediately so partial results
survive timeouts and Ctrl+C.
"""

from __future__ import annotations

import abc
import logging
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Sequence
from typing import Any, ClassVar

import httpx

from allfinder.core.context import RunContext
from allfinder.core.http import AuthError, HttpError, RateLimited, fetch
from allfinder.core.models import Finding, Requirement, SourceKind, Target
from allfinder.core.normalize import extract_hostnames, normalize_hostname, split_names
from allfinder.utils.subprocess import ProcResult, run_stream

__all__ = [
    "AuthError",
    "BinaryPlugin",
    "HttpError",
    "HttpPlugin",
    "Plugin",
    "RateLimited",
    "SkipPlugin",
]


class SkipPlugin(Exception):
    """Raise from ``run`` to mark the source as *skipped* with a reason."""


class Plugin(abc.ABC):
    """Base class for every source.  Subclasses set the class attributes."""

    name: ClassVar[str] = ""
    kind: ClassVar[SourceKind] = SourceKind.PASSIVE
    description: ClassVar[str] = ""
    requires: ClassVar[Requirement] = {}
    default_timeout: ClassVar[int] = 60
    rate_limit: ClassVar[float | None] = None  # requests per second to the API host
    weight: ClassVar[int] = 1  # higher = scheduled earlier
    recursive: ClassVar[bool] = False  # cheap enough to re-run on sub-roots
    needs_resolved: ClassVar[bool] = False  # active/enrich plugin wants resolved hosts
    tags: ClassVar[tuple[str, ...]] = ()

    def __init__(self) -> None:
        self.log = logging.getLogger(f"allfinder.plugin.{self.name or type(self).__name__}")

    # -- availability -----------------------------------------------------
    def check(self, ctx: RunContext) -> str | None:
        """Return a human reason why the plugin cannot run, or ``None`` if it can."""
        req = self.requires or {}
        for b in req.get("binaries", []):
            if ctx.binary(b) is None:
                return f"binary not found: {b} (run: allfinder doctor)"
        for k in req.get("api_keys", []):
            if not ctx.keys.has(k):
                return f"no API key: {k}"
        return None

    def missing_requirements(self, keys: Any, binary_lookup: Any) -> list[str]:
        """Used by ``sources --available`` / ``doctor`` outside a run."""
        missing: list[str] = []
        for b in (self.requires or {}).get("binaries", []):
            if binary_lookup(b) is None:
                missing.append(f"binary:{b}")
        for k in (self.requires or {}).get("api_keys", []):
            if not keys.has(k):
                missing.append(f"key:{k}")
        return missing

    # -- main entry point -------------------------------------------------
    @abc.abstractmethod
    def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        """Yield findings for *target*.  Must be an ``async def`` generator."""

    # -- helpers for subclasses ------------------------------------------
    def finding(
        self,
        raw: str | None,
        *,
        ips: Iterable[str] | None = None,
        cname: str | None = None,
        extra: dict[str, Any] | None = None,
        source: str | None = None,
    ) -> Finding | None:
        host = normalize_hostname(raw)
        if not host:
            return None
        return Finding(
            hostname=host,
            source=source or self.name,
            ips=[ip for ip in (ips or []) if ip],
            cname=normalize_hostname(cname) if cname else None,
            extra=extra or {},
        )

    def findings_from_values(
        self,
        values: Iterable[str | None],
        target: Target,
        *,
        in_scope_only: bool = True,
    ) -> Iterator[Finding]:
        """Normalize raw strings (splitting newline/comma blobs) into findings."""
        seen: set[str] = set()
        for raw in values:
            if not raw:
                continue
            for part in split_names(raw):
                host = normalize_hostname(part)
                if not host or host in seen:
                    continue
                if in_scope_only and not _under(host, target):
                    continue
                seen.add(host)
                yield Finding(hostname=host, source=self.name)

    def findings_from_text(self, text: str, target: Target) -> Iterator[Finding]:
        """Regex-extract every in-scope hostname from arbitrary text."""
        for host in sorted(extract_hostnames(text, target.roots or (target.root,))):
            yield Finding(hostname=host, source=self.name)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"


def _under(host: str, target: Target) -> bool:
    for root in target.roots or (target.root,):
        if host == root or host.endswith("." + root):
            return True
    return False


# --------------------------------------------------------------------------- HTTP API plugins


class HttpPlugin(Plugin):
    """Plugin backed by HTTP APIs: rate limiting, retries and key rotation."""

    key_provider: ClassVar[str | None] = None  # key-ring entry to use/rotate
    retries: ClassVar[int] = 2

    async def request(
        self,
        ctx: RunContext,
        method: str,
        url: str,
        *,
        ok: Iterable[int] | None = None,
        rate: float | None = None,
        rate_key: str | None = None,
        key: str | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """One request through the shared client; on 401/403/429 the key is rotated."""
        try:
            return await fetch(
                ctx.http,
                method,
                url,
                retries=self.retries,
                limiter=ctx.limiter,
                rate=self.rate_limit if rate is None else rate,
                rate_key=rate_key,
                ok=ok,
                backoff=ctx.config.http.backoff,
                **kwargs,
            )
        except (AuthError, RateLimited) as exc:
            if key and self.key_provider:
                ctx.keys.mark_bad(self.key_provider, key)
            raise exc

    async def get(self, ctx: RunContext, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request(ctx, "GET", url, **kwargs)

    async def get_json(self, ctx: RunContext, url: str, **kwargs: Any) -> Any:
        resp = await self.get(ctx, url, **kwargs)
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {url}", status=resp.status_code, url=url) from exc

    async def get_text(self, ctx: RunContext, url: str, **kwargs: Any) -> str:
        resp = await self.get(ctx, url, **kwargs)
        return resp.text

    async def stream_lines(
        self,
        ctx: RunContext,
        url: str,
        *,
        method: str = "GET",
        ok: Iterable[int] | None = None,
        max_lines: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream a (potentially huge) text response line by line."""
        await ctx.limiter.acquire(url.split("/")[2] if "//" in url else url, self.rate_limit)
        ok_set = set(ok or ())
        n = 0
        async with ctx.http.stream(method, url, **kwargs) as resp:
            if resp.status_code >= 400 and resp.status_code not in ok_set:
                await resp.aread()
                body = resp.text[:200].replace("\n", " ")
                msg = f"HTTP {resp.status_code} for {url}: {body}"
                if resp.status_code == 429:
                    raise RateLimited(msg, status=resp.status_code, url=url)
                if resp.status_code in (401, 403):
                    raise AuthError(msg, status=resp.status_code, url=url)
                raise HttpError(msg, status=resp.status_code, url=url)
            async for line in resp.aiter_lines():
                line = line.rstrip("\r")
                if not line:
                    continue
                yield line
                n += 1
                if max_lines is not None and n >= max_lines:
                    break

    def key(self, ctx: RunContext) -> str | None:
        return ctx.keys.get(self.key_provider) if self.key_provider else None

    def require_key(self, ctx: RunContext) -> str:
        key = self.key(ctx)
        if not key:
            raise SkipPlugin(f"no API key: {self.key_provider}")
        return key

    async def keyed_request(
        self,
        ctx: RunContext,
        method: str,
        url: str,
        *,
        auth: Callable[[str], dict[str, Any]],
        **kwargs: Any,
    ) -> httpx.Response:
        """Request with key rotation: ``auth(key)`` returns request kwargs to merge
        (e.g. ``{"headers": {"X-Key": key}}`` or ``{"params": {"key": key}}``).
        On 401/403/429 the key is blacklisted and the next one is tried."""
        attempts = max(1, ctx.keys.count(self.key_provider or ""))
        last: Exception | None = None
        for _ in range(attempts):
            key = self.require_key(ctx)
            merged = dict(kwargs)
            for k, v in auth(key).items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
            try:
                return await self.request(ctx, method, url, key=key, **merged)
            except (AuthError, RateLimited) as exc:
                last = exc
                if ctx.keys.usable(self.key_provider or "") == 0:
                    raise
        assert last is not None
        raise last

    async def keyed_json(
        self,
        ctx: RunContext,
        url: str,
        *,
        auth: Callable[[str], dict[str, Any]],
        method: str = "GET",
        **kwargs: Any,
    ) -> Any:
        resp = await self.keyed_request(ctx, method, url, auth=auth, **kwargs)
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {url}", status=resp.status_code, url=url) from exc


# --------------------------------------------------------------------------- binary wrappers


class BinaryPlugin(Plugin):
    """Plugin that wraps an external executable and parses its stdout."""

    binary: ClassVar[str] = ""

    def check(self, ctx: RunContext) -> str | None:
        reason = super().check(ctx)
        if reason:
            return reason
        if self.binary and ctx.binary(self.binary) is None:
            return f"binary not found: {self.binary} (run: allfinder doctor)"
        return None

    def path(self, ctx: RunContext) -> str:
        p = ctx.binary(self.binary)
        if p is None:
            raise SkipPlugin(f"binary not found: {self.binary}")
        return p

    async def lines(
        self,
        ctx: RunContext,
        args: Sequence[str],
        *,
        timeout: float | None = None,
        stdin_data: str | bytes | None = None,
        env: dict[str, str] | None = None,
        result: ProcResult | None = None,
        check: bool = True,
    ) -> AsyncIterator[str]:
        """Run ``<binary> *args`` and stream stdout lines."""
        cmd = [self.path(ctx), *args]
        to = timeout if timeout is not None else ctx.timeout_for(self.name, self.default_timeout)
        ctx.log.debug("%s: %s", self.name, " ".join(cmd))
        async for line in run_stream(
            cmd,
            timeout=to,
            stdin_data=stdin_data,
            env=env,
            cwd=ctx.tmpdir,
            result=result,
            check=check,
        ):
            yield line
