"""Terminal UI: live per-source table on a TTY, plain append-only lines otherwise.

Everything decorative goes to **stderr** so stdout stays clean for
``--silent`` (hostnames) and ``--json-lines`` (records).
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from allfinder import __version__
from allfinder.core.models import Finding, SourceStats, SourceStatus
from allfinder.utils.text import human_duration, human_int, truncate

_STATUS_STYLE = {
    SourceStatus.PENDING: ("dim", "·"),
    SourceStatus.RUNNING: ("cyan", "*"),
    SourceStatus.DONE: ("green", "+"),
    SourceStatus.SKIPPED: ("yellow", "!"),
    SourceStatus.TIMEOUT: ("red", "!"),
    SourceStatus.ERROR: ("red", "!"),
}


class UI:
    def __init__(
        self,
        *,
        silent: bool = False,
        json_lines: bool = False,
        no_color: bool = False,
        quiet: bool = False,
        force_plain: bool | None = None,
    ) -> None:
        self.silent = silent
        self.json_lines = json_lines
        self.quiet = quiet or silent or json_lines
        self.err = Console(stderr=True, no_color=no_color, force_terminal=None, highlight=False)
        self.out = Console(file=sys.stdout, no_color=True, highlight=False, soft_wrap=True)
        is_tty = self.err.is_terminal and not no_color
        self.plain = (not is_tty) if force_plain is None else force_plain
        self._stats: dict[str, SourceStats] = {}
        self._order: list[str] = []
        self._printed: dict[str, SourceStatus] = {}
        self._live: Live | None = None
        self._lock = threading.Lock()
        self._messages: list[tuple[str, str]] = []

    # ------------------------------------------------------------------ lifecycle
    def header(self, roots: Iterable[str], mode: str) -> None:
        if self.quiet:
            return
        roots_txt = ", ".join(roots)
        self.err.print(
            f"[bold]allfinder[/bold] v{__version__}  target: [bold]{roots_txt}[/bold]  mode: {mode}"
        )

    def start(self) -> None:
        if self.quiet or self.plain:
            return
        self._live = Live(self._table(), console=self.err, refresh_per_second=6, transient=False)
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.update(self._table(), refresh=True)
            self._live.stop()
            self._live = None

    # ------------------------------------------------------------------ callbacks
    def on_stats(self, stats: SourceStats) -> None:
        with self._lock:
            if stats.source not in self._stats:
                self._order.append(stats.source)
            self._stats[stats.source] = stats
        if self.quiet:
            return
        if self.plain:
            self._plain_line(stats)
        elif self._live is not None:
            self._live.update(self._table())

    def on_log(self, level: str, message: str) -> None:
        if self.quiet:
            if level in ("error", "warning", "warn"):
                self.err.print(f"[yellow][!][/yellow] {message}")
            return
        style = {"error": "red", "warning": "yellow", "warn": "yellow"}.get(level, "dim")
        if self._live is not None:
            self._live.console.print(f"[{style}]{message}[/{style}]")
        else:
            self.err.print(f"[{style}]{message}[/{style}]")

    def on_finding(self, finding: Finding, is_new: bool) -> None:
        if not is_new:
            return
        if self.silent:
            self.out.file.write(finding.hostname + "\n")
            self.out.file.flush()
        elif self.json_lines:
            rec: dict[str, object] = {"hostname": finding.hostname, "source": finding.source}
            if finding.ips:
                rec["ips"] = finding.ips
            if finding.cname:
                rec["cname"] = finding.cname
            self.out.file.write(json.dumps(rec) + "\n")
            self.out.file.flush()

    # ------------------------------------------------------------------ rendering
    def _plain_line(self, s: SourceStats) -> None:
        prev = self._printed.get(s.source)
        if prev == s.status and s.status != SourceStatus.RUNNING:
            return
        if s.status == SourceStatus.RUNNING and prev == SourceStatus.RUNNING:
            return  # no progress spam when piped
        self._printed[s.source] = s.status
        _, sym = _STATUS_STYLE[s.status]
        line = f"[{sym}] {s.source:<16} {s.status.value:<8}"
        if s.status in (SourceStatus.DONE, SourceStatus.ERROR, SourceStatus.TIMEOUT):
            line += f" {s.found:>6} found {s.unique:>6} new  {human_duration(s.duration):>7}"
        if s.error:
            line += f"  {truncate(s.error, 80)}"
        self.err.print(line, markup=False)

    def _table(self) -> Table:
        t = Table(box=None, pad_edge=False, show_header=True, header_style="bold dim")
        t.add_column("")
        t.add_column("source", min_width=14)
        t.add_column("status", min_width=8)
        t.add_column("found", justify="right", min_width=6)
        t.add_column("new", justify="right", min_width=6)
        t.add_column("time", justify="right", min_width=7)
        t.add_column("note", overflow="fold")
        with self._lock:
            items = [self._stats[n] for n in self._order]
        for s in items:
            style, sym = _STATUS_STYLE[s.status]
            note = truncate(s.error, 70) if s.error else ""
            t.add_row(
                Text(f"[{sym}]", style=style),
                s.source,
                Text(s.status.value, style=style),
                human_int(s.found) if s.status != SourceStatus.PENDING else "",
                human_int(s.unique) if s.status != SourceStatus.PENDING else "",
                human_duration(s.duration) if s.status != SourceStatus.PENDING else "",
                Text(note, style="dim"),
            )
        return t

    def summary(
        self,
        stats: Iterable[SourceStats],
        counts: Mapping[str, int],
        out_dir: Path | None,
        *,
        elapsed: float,
        interrupted: bool = False,
    ) -> None:
        if self.quiet:
            return
        t = Table(title=None, box=None, header_style="bold", pad_edge=False)
        t.add_column("Source", min_width=16)
        t.add_column("Status", min_width=8)
        t.add_column("Found", justify="right")
        t.add_column("Unique", justify="right")
        t.add_column("Time", justify="right")
        t.add_column("Note")
        rows = sorted(stats, key=lambda s: (-s.unique, -s.found, s.source))
        for s in rows:
            style, _ = _STATUS_STYLE[s.status]
            t.add_row(
                s.source,
                Text(s.status.value, style=style),
                human_int(s.found),
                human_int(s.unique),
                human_duration(s.duration),
                Text(truncate(s.error, 60) if s.error else "", style="dim"),
            )
        self.err.print()
        self.err.print(t)
        self.err.print()
        line = (
            f"Total unique: [bold]{human_int(counts.get('total', 0))}[/bold]"
            f"   New this run: {human_int(counts.get('new_this_run', 0))}"
            f"   Resolved: {human_int(counts.get('resolved', 0))}"
            f"   Wildcard-only: {human_int(counts.get('wildcard', 0))}"
            f"   Alive: {human_int(counts.get('alive', 0))}"
            f"   Time: {human_duration(elapsed)}"
        )
        if counts.get("related"):
            line += f"   Related domains: {human_int(counts['related'])}"
        self.err.print(line)
        if interrupted:
            self.err.print("[yellow]Interrupted: partial results were written.[/yellow]")
        if out_dir is not None:
            self.err.print(f"Output: [bold]{out_dir}[/bold]")

    def print(self, *args: object, **kwargs: object) -> None:
        self.err.print(*args, **kwargs)  # type: ignore[arg-type]
