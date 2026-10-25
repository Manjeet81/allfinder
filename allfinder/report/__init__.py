"""Report writers: everything lands in ``out/<domain>/<timestamp>/`` as plain files."""

from __future__ import annotations

from pathlib import Path

from allfinder.core.models import RunInfo, SourceStats, Subdomain
from allfinder.report.csv import write_csv_report
from allfinder.report.json import write_json_reports
from allfinder.report.txt import write_sources_txt, write_txt_reports

__all__ = ["write_all_reports"]


def write_all_reports(
    out_dir: Path,
    *,
    subs: list[Subdomain],
    related: list[str],
    stats: list[SourceStats],
    run: RunInfo,
    counts: dict[str, int],
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = write_txt_reports(out_dir, subs, related)
    files.update(write_json_reports(out_dir, subs, stats, run, counts, related))
    files["results.csv"] = write_csv_report(out_dir, subs)
    files["sources.txt"] = write_sources_txt(out_dir, stats)
    return files
