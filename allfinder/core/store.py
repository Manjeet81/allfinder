"""SQLite-backed result store with an in-memory cache for fast dedup.

One database per output root (``~/.allfinder/allfinder.db`` by default)
keeps every target, run, subdomain and per-source finding so runs are
resumable and diffable.  Writes are batched and committed every few hundred
rows (or on :meth:`flush`) so partial results survive Ctrl+C.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from allfinder.core.models import (
    Finding,
    HttpInfo,
    Resolution,
    RunInfo,
    SourceStats,
    SourceStatus,
    Subdomain,
    utcnow,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    root_domain TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    roots_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    args_json TEXT NOT NULL DEFAULT '{}',
    version TEXT NOT NULL DEFAULT '',
    out_dir TEXT
);
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY,
    hostname TEXT UNIQUE NOT NULL,
    root TEXT NOT NULL,
    first_seen_run TEXT,
    last_seen_run TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    wildcard INTEGER NOT NULL DEFAULT 0,
    cname TEXT,
    ips_json TEXT NOT NULL DEFAULT '[]',
    asn TEXT,
    org TEXT,
    http_json TEXT,
    takeover_json TEXT,
    depth INTEGER NOT NULL DEFAULT 0,
    in_scope INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_subdomains_root ON subdomains(root);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    ts TEXT NOT NULL,
    UNIQUE(run_id, hostname, source)
);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(hostname);
CREATE TABLE IF NOT EXISTS source_stats (
    run_id TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    found INTEGER NOT NULL DEFAULT 0,
    unique_count INTEGER NOT NULL DEFAULT 0,
    duration REAL NOT NULL DEFAULT 0,
    error TEXT,
    PRIMARY KEY (run_id, source)
);
"""


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return utcnow()
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


class Store:
    """Thread-safe (single writer) SQLite DAO + in-memory ``Subdomain`` cache."""

    COMMIT_EVERY = 250
    COMMIT_SECONDS = 2.0

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._pending = 0
        self._last_commit = time.monotonic()
        self._in_tx = False
        self._cache: dict[str, Subdomain] = {}
        self._run_sources: dict[str, set[str]] = {}  # hostname -> sources seen this run
        self.run: RunInfo | None = None
        self._init()

    # ------------------------------------------------------------------ setup
    def _init(self) -> None:
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    def _begin(self) -> None:
        if not self._in_tx:
            self._conn.execute("BEGIN")
            self._in_tx = True

    def _maybe_commit(self) -> None:
        self._pending += 1
        if (
            self._pending >= self.COMMIT_EVERY
            or time.monotonic() - self._last_commit > self.COMMIT_SECONDS
        ):
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if self._in_tx:
                self._conn.execute("COMMIT")
                self._in_tx = False
            self._pending = 0
            self._last_commit = time.monotonic()

    def close(self) -> None:
        with self._lock:
            try:
                self.flush()
            finally:
                self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ runs
    def start_run(
        self,
        roots: Iterable[str],
        *,
        args: dict[str, Any] | None = None,
        version: str = "",
        out_dir: str | Path | None = None,
        run_id: str | None = None,
    ) -> RunInfo:
        roots_t = tuple(roots)
        run = RunInfo(
            id=run_id or new_run_id(),
            roots=roots_t,
            args=dict(args or {}),
            version=version,
            out_dir=str(out_dir) if out_dir else None,
        )
        with self._lock:
            self._begin()
            now = _iso(run.started_at)
            for root in roots_t:
                self._conn.execute(
                    "INSERT OR IGNORE INTO targets(root_domain, created_at) VALUES (?, ?)",
                    (root, now),
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO runs(id, roots_json, started_at, finished_at, args_json, version, out_dir)"  # noqa: E501
                " VALUES (?, ?, ?, NULL, ?, ?, ?)",
                (
                    run.id,
                    json.dumps(list(roots_t)),
                    now,
                    json.dumps(run.args, default=str),
                    version,
                    run.out_dir,
                ),
            )
            self.flush()
            self.run = run
            self._run_sources.clear()
            self.load(roots_t)
        return run

    def finish_run(self, run_id: str | None = None) -> None:
        rid = run_id or (self.run.id if self.run else None)
        if rid is None:
            return
        with self._lock:
            self._begin()
            now = utcnow()
            self._conn.execute("UPDATE runs SET finished_at=? WHERE id=?", (_iso(now), rid))
            self.flush()
            if self.run and self.run.id == rid:
                self.run.finished_at = now

    def runs(self, root: str | None = None) -> list[RunInfo]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM runs ORDER BY started_at").fetchall()
        out: list[RunInfo] = []
        for r in rows:
            roots = tuple(json.loads(r["roots_json"]))
            if root is not None and root not in roots:
                continue
            out.append(
                RunInfo(
                    id=r["id"],
                    roots=roots,
                    started_at=_parse_dt(r["started_at"]),
                    finished_at=_parse_dt(r["finished_at"]) if r["finished_at"] else None,
                    args=json.loads(r["args_json"] or "{}"),
                    version=r["version"] or "",
                    out_dir=r["out_dir"],
                )
            )
        return out

    def get_run(self, run_id: str) -> RunInfo | None:
        for r in self.runs():
            if r.id == run_id:
                return r
        return None

    # ------------------------------------------------------------------ cache
    def load(self, roots: Iterable[str]) -> int:
        """Populate the cache with every known subdomain under *roots*."""
        count = 0
        with self._lock:
            for root in roots:
                rows = self._conn.execute(
                    "SELECT * FROM subdomains WHERE root=?", (root,)
                ).fetchall()
                for row in rows:
                    sub = self._row_to_sub(row)
                    self._cache[sub.hostname] = sub
                    count += 1
        return count

    def _row_to_sub(self, row: sqlite3.Row) -> Subdomain:
        hostname = row["hostname"]
        with self._lock:
            srcs = self._conn.execute(
                "SELECT DISTINCT source FROM findings WHERE hostname=?", (hostname,)
            ).fetchall()
        http = json.loads(row["http_json"]) if row["http_json"] else None
        return Subdomain(
            hostname=hostname,
            root=row["root"],
            sources={s["source"] for s in srcs},
            first_seen=_parse_dt(row["first_seen"]),
            last_seen=_parse_dt(row["last_seen"]),
            resolved=bool(row["resolved"]),
            wildcard=bool(row["wildcard"]),
            ips=json.loads(row["ips_json"] or "[]"),
            cname=row["cname"],
            asn=row["asn"],
            org=row["org"],
            http=HttpInfo(**http) if http else None,
            takeover=json.loads(row["takeover_json"]) if row["takeover_json"] else None,
            depth=int(row["depth"] or 0),
            in_scope=bool(row["in_scope"]),
        )

    def __contains__(self, hostname: object) -> bool:
        return isinstance(hostname, str) and hostname in self._cache

    def __len__(self) -> int:
        return len(self._cache)

    def get(self, hostname: str) -> Subdomain | None:
        return self._cache.get(hostname)

    # ------------------------------------------------------------------ writes
    def add_finding(
        self,
        finding: Finding,
        *,
        root: str,
        depth: int = 0,
        in_scope: bool = True,
    ) -> bool:
        """Record *finding*; return ``True`` if the hostname is new to the store."""
        run_id = self.run.id if self.run else None
        host = finding.hostname
        now = finding.ts or utcnow()
        with self._lock:
            self._begin()
            sub = self._cache.get(host)
            is_new = sub is None
            if sub is None:
                sub = Subdomain(
                    hostname=host,
                    root=root,
                    first_seen=now,
                    last_seen=now,
                    depth=depth,
                    in_scope=in_scope,
                )
                if finding.ips:
                    sub.ips = list(dict.fromkeys(finding.ips))
                if finding.cname:
                    sub.cname = finding.cname
                self._cache[host] = sub
                self._conn.execute(
                    "INSERT OR IGNORE INTO subdomains(hostname, root, first_seen_run, last_seen_run,"  # noqa: E501
                    " first_seen, last_seen, cname, ips_json, depth, in_scope)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        host,
                        root,
                        run_id,
                        run_id,
                        _iso(now),
                        _iso(now),
                        sub.cname,
                        json.dumps(sub.ips),
                        depth,
                        int(in_scope),
                    ),
                )
            else:
                sub.last_seen = now
                if finding.ips:
                    for ip in finding.ips:
                        if ip not in sub.ips:
                            sub.ips.append(ip)
                if finding.cname and not sub.cname:
                    sub.cname = finding.cname
                self._conn.execute(
                    "UPDATE subdomains SET last_seen=?, last_seen_run=?, cname=COALESCE(cname, ?), ips_json=?"  # noqa: E501
                    " WHERE hostname=?",
                    (_iso(now), run_id, sub.cname, json.dumps(sub.ips), host),
                )
            sub.sources.add(finding.source)
            if run_id is not None:
                self._run_sources.setdefault(host, set()).add(finding.source)
                self._conn.execute(
                    "INSERT OR IGNORE INTO findings(run_id, hostname, source, ts) VALUES (?, ?, ?, ?)",  # noqa: E501
                    (run_id, host, finding.source, _iso(now)),
                )
            self._maybe_commit()
        return is_new

    def seen_this_run(self, hostname: str) -> bool:
        return hostname in self._run_sources

    def update_resolution(self, res: Resolution, *, keep_wildcards: bool = False) -> None:
        sub = self._cache.get(res.hostname)
        if sub is None:
            return
        with self._lock:
            self._begin()
            sub.ips = list(dict.fromkeys(res.ips))
            sub.cname = res.cname[0] if res.cname else sub.cname
            sub.wildcard = res.wildcard
            sub.resolved = res.resolved and (keep_wildcards or not res.wildcard)
            self._conn.execute(
                "UPDATE subdomains SET resolved=?, wildcard=?, cname=?, ips_json=? WHERE hostname=?",  # noqa: E501
                (
                    int(sub.resolved),
                    int(sub.wildcard),
                    sub.cname,
                    json.dumps(sub.ips),
                    sub.hostname,
                ),
            )
            self._maybe_commit()

    def update_http(self, hostname: str, info: HttpInfo | None) -> None:
        sub = self._cache.get(hostname)
        if sub is None:
            return
        with self._lock:
            self._begin()
            sub.http = info
            self._conn.execute(
                "UPDATE subdomains SET http_json=? WHERE hostname=?",
                (json.dumps(info.to_dict()) if info else None, hostname),
            )
            self._maybe_commit()

    def update_takeover(self, hostname: str, data: dict[str, Any] | None) -> None:
        sub = self._cache.get(hostname)
        if sub is None:
            return
        with self._lock:
            self._begin()
            sub.takeover = data
            self._conn.execute(
                "UPDATE subdomains SET takeover_json=? WHERE hostname=?",
                (json.dumps(data) if data else None, hostname),
            )
            self._maybe_commit()

    def update_asn(self, hostname: str, asn: str | None, org: str | None) -> None:
        sub = self._cache.get(hostname)
        if sub is None:
            return
        with self._lock:
            self._begin()
            sub.asn, sub.org = asn, org
            self._conn.execute(
                "UPDATE subdomains SET asn=?, org=? WHERE hostname=?", (asn, org, hostname)
            )
            self._maybe_commit()

    # ------------------------------------------------------------------ reads
    def subdomains(
        self,
        roots: Iterable[str] | None = None,
        *,
        in_scope: bool | None = True,
        resolved: bool | None = None,
        this_run_only: bool = False,
    ) -> list[Subdomain]:
        root_set = set(roots) if roots is not None else None
        out: list[Subdomain] = []
        for sub in self._cache.values():
            if root_set is not None and sub.root not in root_set:
                continue
            if in_scope is not None and sub.in_scope != in_scope:
                continue
            if resolved is not None and sub.resolved != resolved:
                continue
            if this_run_only and sub.hostname not in self._run_sources:
                continue
            out.append(sub)
        out.sort(key=lambda s: s.hostname)
        return out

    def hostnames(self, roots: Iterable[str] | None = None, **kw: Any) -> list[str]:
        return [s.hostname for s in self.subdomains(roots, **kw)]

    def related_domains(self, roots: Iterable[str] | None = None) -> list[str]:
        return [s.hostname for s in self.subdomains(roots, in_scope=False)]

    def new_since(self, run_id: str, roots: Iterable[str] | None = None) -> list[str]:
        """Hostnames first seen *after* the run *run_id* started."""
        baseline = self.get_run(run_id)
        if baseline is None:
            raise KeyError(run_id)
        since = baseline.started_at
        out = [
            s.hostname
            for s in self.subdomains(roots)
            if s.first_seen > since and s.hostname not in self._first_seen_in(run_id)
        ]
        return sorted(out)

    def _first_seen_in(self, run_id: str, roots: Iterable[str] | None = None) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT hostname, root FROM subdomains WHERE first_seen_run=? AND in_scope=1",
                (run_id,),
            ).fetchall()
        root_set = set(roots) if roots is not None else None
        return {r["hostname"] for r in rows if root_set is None or r["root"] in root_set}

    def first_seen_in_run(self, run_id: str, roots: Iterable[str] | None = None) -> list[str]:
        return sorted(self._first_seen_in(run_id, roots))

    # ------------------------------------------------------------------ stats
    def save_stats(self, stats: SourceStats, run_id: str | None = None) -> None:
        rid = run_id or (self.run.id if self.run else None)
        if rid is None:
            return
        with self._lock:
            self._begin()
            self._conn.execute(
                "INSERT OR REPLACE INTO source_stats(run_id, source, status, found, unique_count, duration, error)"  # noqa: E501
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    rid,
                    stats.source,
                    stats.status.value,
                    stats.found,
                    stats.unique,
                    stats.duration,
                    stats.error,
                ),
            )
            self._maybe_commit()

    def stats(self, run_id: str | None = None) -> list[SourceStats]:
        rid = run_id or (self.run.id if self.run else None)
        if rid is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM source_stats WHERE run_id=? ORDER BY source", (rid,)
            ).fetchall()
        return [
            SourceStats(
                source=r["source"],
                status=SourceStatus(r["status"]),
                found=r["found"],
                unique=r["unique_count"],
                duration=r["duration"],
                error=r["error"],
            )
            for r in rows
        ]

    def counts(self, roots: Iterable[str] | None = None) -> dict[str, int]:
        subs = self.subdomains(roots)
        return {
            "total": len(subs),
            "resolved": sum(1 for s in subs if s.resolved),
            "wildcard": sum(1 for s in subs if s.wildcard),
            "alive": sum(1 for s in subs if s.alive),
            "related": len(self.related_domains(roots)),
            "new_this_run": sum(1 for s in subs if self.run and s.hostname in self._run_sources),
        }
