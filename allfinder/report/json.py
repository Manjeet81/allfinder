"""``results.json`` (full document) and ``results.jsonl`` (one record per line)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from allfinder.core.models import RunInfo, SourceStats, Subdomain


def write_json_reports(
    out_dir: Path,
    subs: list[Subdomain],
    stats: list[SourceStats],
    run: RunInfo,
    counts: Mapping[str, int],
    related: list[str],
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = [s.to_dict() for s in sorted(subs, key=lambda s: s.hostname)]
    doc: dict[str, Any] = {
        "run": {
            "id": run.id,
            "roots": list(run.roots),
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "version": run.version,
            "args": run.args,
        },
        "counts": dict(counts),
        "sources": [s.to_dict() for s in sorted(stats, key=lambda s: s.source)],
        "related_domains": sorted(related),
        "subdomains": records,
    }
    p_json = out_dir / "results.json"
    with p_json.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, default=str)
        fh.write("\n")
    p_jsonl = out_dir / "results.jsonl"
    with p_jsonl.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, default=str))
            fh.write("\n")
    return {"results.json": p_json, "results.jsonl": p_jsonl}
