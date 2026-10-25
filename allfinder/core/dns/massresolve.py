"""Mass resolution stage: wildcard detection -> resolve -> filter -> store.

Backend preference: ``puredns resolve`` > ``massdns`` > native aiodns pool.
The native pool is always used for wildcard probing and re-validation.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from pathlib import Path

from allfinder.core import binaries
from allfinder.core.context import RunContext
from allfinder.core.dns.massdns_parse import parse_any, parse_massdns_json
from allfinder.core.dns.resolver_pool import ResolverPool
from allfinder.core.dns.wildcard import WildcardDetector
from allfinder.core.models import Resolution, SourceStats, SourceStatus, utcnow
from allfinder.core.runner import get_book
from allfinder.core.wordlists import load_resolvers, path_for
from allfinder.utils.subprocess import run_capture

log = logging.getLogger("allfinder.resolve")

RESOLVE_SOURCE = "resolve"
BATCH = 50_000


def get_pool(ctx: RunContext) -> ResolverPool:
    """Lazily build the shared resolver pool for this run."""
    if ctx.resolver_pool is None:
        resolvers = load_resolvers(ctx.config, ctx.options.resolvers)
        trusted = load_resolvers(ctx.config, ctx.options.trusted_resolvers, trusted=True)
        ctx.resolver_pool = ResolverPool(
            resolvers,
            trusted=trusted,
            qps=ctx.options.qps,
            concurrency=min(1000, max(50, ctx.options.qps)),
            ipv6=bool(ctx.extras.get("ipv6", False)),
        )
        ctx.log.debug("resolver pool: %d resolvers, %d trusted", len(resolvers), len(trusted))
    return ctx.resolver_pool


def get_detector(ctx: RunContext) -> WildcardDetector:
    det = ctx.extras.get("wildcard_detector")
    if det is None:
        det = ctx.extras["wildcard_detector"] = WildcardDetector(get_pool(ctx).resolve)
    return det


def attempted(ctx: RunContext) -> set[str]:
    s = ctx.extras.get("resolve_attempted")
    if s is None:
        s = ctx.extras["resolve_attempted"] = set()
    return s


# --------------------------------------------------------------------------- backends


def external_backend(ctx: RunContext) -> str | None:
    if ctx.extras.get("force_native_resolver"):
        return None
    for name in ("puredns", "massdns"):
        if binaries.which(name) and binaries.supported_on_this_os(name):
            return name
    return None


async def _resolve_external(
    ctx: RunContext, backend: str, hosts: list[str], resolvers_file: Path
) -> dict[str, Resolution]:
    tmp = ctx.tmpdir
    tmp.mkdir(parents=True, exist_ok=True)
    stamp = f"{int(time.time() * 1000)}"
    in_file = tmp / f"resolve-{stamp}.txt"
    in_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    out_file = tmp / f"resolve-{stamp}.out"
    timeout = ctx.timeout_for(RESOLVE_SOURCE, 3600)
    if backend == "puredns":
        cmd = [
            binaries.which("puredns") or "puredns",
            "resolve",
            str(in_file),
            "-r",
            str(resolvers_file),
            "--write-massdns",
            str(out_file),
            "--wildcard-tests",
            "50",
            "--rate-limit",
            str(ctx.options.qps),
            "-q",
        ]
        trusted = ctx.options.trusted_resolvers
        if trusted and Path(trusted).is_file():
            cmd += ["--resolvers-trusted", trusted]
    else:
        cmd = [
            binaries.which("massdns") or "massdns",
            "-r",
            str(resolvers_file),
            "-t",
            "A",
            "-o",
            "J",
            "-q",
            "-s",
            str(max(100, ctx.options.qps * 2)),
            "-w",
            str(out_file),
            str(in_file),
        ]
    await run_capture(cmd, timeout=timeout, check=False, cwd=tmp)
    if not out_file.is_file():
        return {}
    with out_file.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    return parse_massdns_json(lines) if backend == "massdns" else parse_any(lines)


def _write_resolvers_file(ctx: RunContext) -> Path:
    override = ctx.options.resolvers
    if override and Path(override).is_file():
        return Path(override)
    downloaded = path_for(ctx.config, "resolvers")
    if downloaded.is_file():
        return downloaded
    p = ctx.tmpdir / "resolvers.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(load_resolvers(ctx.config)) + "\n", encoding="utf-8")
    return p


# --------------------------------------------------------------------------- public API


async def resolve_hosts(
    ctx: RunContext,
    hosts: Iterable[str],
    *,
    root: str,
    stats: SourceStats | None = None,
    validate_hits: bool = False,
) -> dict[str, Resolution]:
    """Resolve *hosts*, flag wildcard-only names, persist into the store.

    ``validate_hits`` re-checks positive answers with trusted resolvers (used
    for brute-force candidates where poisoned public resolvers matter).
    """
    pool = get_pool(ctx)
    detector = get_detector(ctx)
    host_list = [h for h in dict.fromkeys(hosts) if h]
    results: dict[str, Resolution] = {}
    if not host_list:
        return results

    # 1. wildcard zones for every parent level present in the candidate set
    await detector.probe_all(host_list, root)
    zones = detector.wildcard_zones
    if zones:
        ctx.log.info("wildcard zones under %s: %s", root, ", ".join(sorted(zones)))

    # 2. resolve (external backend in batches, else native)
    backend = external_backend(ctx)
    book = get_book(ctx)
    done = 0

    def _store(res: Resolution) -> None:
        nonlocal done
        done += 1
        results[res.hostname] = res
        res.wildcard = detector.classify_sync(res, root)
        ctx.store.update_resolution(res, keep_wildcards=ctx.options.keep_wildcards)
        if stats is not None:
            stats.found = done
            if res.resolved and not res.wildcard:
                stats.unique += 1
            if done % 100 == 0:
                book.progress(stats)

    if backend:
        resolvers_file = _write_resolvers_file(ctx)
        for i in range(0, len(host_list), BATCH):
            if ctx.cancelled:
                break
            batch = host_list[i : i + BATCH]
            try:
                parsed = await _resolve_external(ctx, backend, batch, resolvers_file)
            except Exception as exc:  # fall back to native for this batch
                ctx.log.warning("%s failed (%s); using native resolver", backend, exc)
                parsed = await pool.resolve_many(batch, cancel=ctx.cancel)
            for h in batch:
                _store(parsed.get(h) or Resolution(h))
    else:
        await pool.resolve_many(host_list, on_result=_store, cancel=ctx.cancel)

    # 3. optional trusted re-validation of positives (brute force)
    if validate_hits:
        positives = [h for h, r in results.items() if r.resolved and not r.wildcard]
        confirmed = 0
        for h in positives:
            if ctx.cancelled:
                break
            res = await pool.resolve_trusted(h)
            if res.resolved:
                confirmed += 1
            else:
                results[h] = Resolution(h, error="not confirmed by trusted resolvers")
                ctx.store.update_resolution(results[h])
        if positives:
            ctx.log.debug("trusted re-validation: %d/%d confirmed", confirmed, len(positives))
    attempted(ctx).update(host_list)
    return results


def pending_hosts(ctx: RunContext, *, roots: Iterable[str] | None = None) -> list[str]:
    """In-scope hostnames not yet resolved during this run."""
    seen = attempted(ctx)
    out: list[str] = []
    for sub in ctx.store.subdomains(roots or ctx.scope.roots):
        if sub.hostname in seen:
            continue
        if ctx.options.resume and sub.resolved and not ctx.store.seen_this_run(sub.hostname):
            continue  # resumed run: keep earlier resolutions for untouched names
        out.append(sub.hostname)
    return out


async def resolve_stage(ctx: RunContext) -> None:
    """Pipeline stage 2: resolve everything new, per root, with a UI row."""
    book = get_book(ctx)
    stats = SourceStats(RESOLVE_SOURCE, status=SourceStatus.RUNNING, started_at=utcnow())
    t0 = time.monotonic()
    book.begin(stats)
    try:
        total = 0
        for root in ctx.scope.roots:
            hosts = pending_hosts(ctx, roots=[root])
            if not hosts or ctx.cancelled:
                continue
            total += len(hosts)
            ctx.log.info("resolving %d hosts under %s", len(hosts), root)
            await resolve_hosts(ctx, hosts, root=root, stats=stats)
        stats.found = max(stats.found, total)
        stats.status = SourceStatus.DONE
        pool = ctx.resolver_pool
        if pool is not None and pool.stats.bad_resolvers:
            stats.error = f"{len(pool.stats.bad_resolvers)} resolvers disabled"
    except Exception as exc:  # noqa: BLE001 - never abort the run
        stats.status = SourceStatus.ERROR
        stats.error = f"{type(exc).__name__}: {exc}"[:300]
        log.debug("resolve stage failed", exc_info=True)
    finally:
        stats.duration = time.monotonic() - t0
        stats.finished_at = utcnow()
        book.finish(stats)
