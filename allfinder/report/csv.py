"""``results.csv`` writer."""

from __future__ import annotations

import csv
from pathlib import Path

from allfinder.core.models import Subdomain

COLUMNS = [
    "hostname",
    "root",
    "resolved",
    "wildcard",
    "ips",
    "cname",
    "http_status",
    "http_title",
    "http_tech",
    "asn",
    "org",
    "takeover",
    "sources",
    "first_seen",
    "last_seen",
]


def write_csv_report(out_dir: Path, subs: list[Subdomain]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "results.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        for s in sorted(subs, key=lambda s: s.hostname):
            w.writerow(
                [
                    s.hostname,
                    s.root,
                    int(s.resolved),
                    int(s.wildcard),
                    ";".join(s.ips),
                    s.cname or "",
                    s.http.status if s.http and s.http.status is not None else "",
                    (s.http.title or "") if s.http else "",
                    ";".join(s.http.tech) if s.http else "",
                    s.asn or "",
                    s.org or "",
                    (s.takeover.get("service", "") if s.takeover else ""),
                    ";".join(sorted(s.sources)),
                    s.first_seen.isoformat(),
                    s.last_seen.isoformat(),
                ]
            )
    return path
