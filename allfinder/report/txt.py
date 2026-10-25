"""Plain-text list writers (``grep``-friendly, one hostname per line)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from allfinder.core.models import SourceStats, Subdomain
from allfinder.utils.text import human_duration


def write_lines(path: Path, lines: Iterable[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(line)
            fh.write("\n")
            n += 1
    return n


def write_txt_reports(out_dir: Path, subs: list[Subdomain], related: list[str]) -> dict[str, Path]:
    files: dict[str, Path] = {}
    subs_sorted = sorted(subs, key=lambda s: s.hostname)
    files["subdomains.txt"] = out_dir / "subdomains.txt"
    write_lines(files["subdomains.txt"], (s.hostname for s in subs_sorted))
    files["resolved.txt"] = out_dir / "resolved.txt"
    write_lines(files["resolved.txt"], (s.hostname for s in subs_sorted if s.resolved))
    files["wildcards.txt"] = out_dir / "wildcards.txt"
    write_lines(files["wildcards.txt"], (s.hostname for s in subs_sorted if s.wildcard))
    files["alive.txt"] = out_dir / "alive.txt"
    write_lines(
        files["alive.txt"],
        ((s.http.url if s.http and s.http.url else s.hostname) for s in subs_sorted if s.alive),
    )
    files["related_domains.txt"] = out_dir / "related_domains.txt"
    write_lines(files["related_domains.txt"], sorted(related))
    return files


def write_sources_txt(out_dir: Path, stats: list[SourceStats]) -> Path:
    path = out_dir / "sources.txt"
    rows = sorted(stats, key=lambda s: (-s.unique, -s.found, s.source))
    lines = [f"{'source':<20} {'status':<8} {'found':>8} {'unique':>8} {'time':>8}  note"]
    for s in rows:
        lines.append(
            f"{s.source:<20} {s.status.value:<8} {s.found:>8} {s.unique:>8} {human_duration(s.duration):>8}"  # noqa: E501
            f"  {s.error or ''}".rstrip()
        )
    write_lines(path, lines)
    return path
