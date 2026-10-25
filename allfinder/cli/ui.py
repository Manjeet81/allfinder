"""Terminal UI: a live, auto-refreshing dashboard on a TTY, plain lines otherwise.

Everything decorative goes to **stderr** so stdout stays clean for
``--silent`` (hostnames) and ``--json-lines`` (records).
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from rich.console import Console, Group
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
    SourceStatus.TIMEOUT: ("red", "x"),
    SourceStatus.ERROR: ("red", "x"),
}
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_DONE_STATES = (SourceStatus.DONE, SourceStatus.ERROR, SourceStatus.TIMEOUT)


def _mmss(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


class _Dashboard:
    """A renderable that rebuilds itself each frame, so the spinner and the
    elapsed clock tick live even while every source is just waiting."""

    def __init__(self, ui: UI) -> None:
        self.ui = ui

    def __rich_console__(self, console: Console, options: object):  # type: ignore[override]
        yield self.ui._render()


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
        self._start = time.monotonic()
        self._roots = ""
        self._mode = ""

    # ------------------------------------------------------------------ lifecycle
    def header(self, roots: Iterable[str], mode: str) -> None:
        self._roots = ", ".join(roots)
        self._mode = mode
        self._start = time.monotonic()
        if self.quiet:
            return
        self.err.print()
        self.err.print(
            f"  [bold cyan]allfinder[/bold cyan] [dim]v{__version__}[/dim]   "
            f"target [bold]{self._roots}[/bold]   mode [bold]{mode}[/bold]"
        )
        if self.plain:
            self.err.print("  [dim]working...[/dim]")

    def start(self) -> None:
        if self.quiet or self.plain:
            return
        self._live = Live(
            _Dashboard(self),
            console=self.err,
            refresh_per_second=12,
            transient=False,
            auto_refresh=True,
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            try:
                self._live.update(self._render(final=True), refresh=True)
            finally:
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
        # live mode auto-refreshes; no explicit update needed

    def on_log(self, level: str, message: str) -> None:
        if self.quiet:
            if level in ("error", "warning", "warn"):
                self.err.print(f"[yellow][!][/yellow] {message}")
            return
        style = {"error": "red", "warning": "yellow", "warn": "yellow"}.get(level, "dim")
        if self._live is not None:
            self._live.console.print(f"  [{style}]{message}[/{style}]")
        else:
            self.err.print(f"  [{style}]{message}[/{style}]")

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
    def _snapshot(self) -> list[SourceStats]:
        with self._lock:
            return [self._stats[n] for n in self._order]

    def _render(self, *, final: bool = False):
        """Build the whole live view (table + ticking footer) fresh each frame."""
        items = self._snapshot()
        spin = _SPINNER[int(time.monotonic() * 10) % len(_SPINNER)]

        # running rows first, then the rest in arrival order, so activity stays on top
        running = [s for s in items if s.status is SourceStatus.RUNNING]
        others = [s for s in items if s.status is not SourceStatus.RUNNING]
        ordered = running + others

        t = Table(box=None, pad_edge=False, show_header=True, header_style="bold dim", expand=False)
        t.add_column(" ", width=1)
        t.add_column("source", min_width=16)
        t.add_column("status", min_width=8)
        t.add_column("found", justify="right", min_width=6)
        t.add_column("new", justify="right", min_width=6)
        t.add_column("time", justify="right", min_width=7)
        t.add_column("note", overflow="fold")
        for s in ordered:
            style, sym = _STATUS_STYLE[s.status]
            mark = spin if s.status is SourceStatus.RUNNING else sym
            note = truncate(s.error, 64) if s.error else ""
            t.add_row(
                Text(mark, style=style),
                s.source,
                Text(s.status.value, style=style),
                human_int(s.found) if s.status is not SourceStatus.PENDING else "",
                human_int(s.unique) if s.status is not SourceStatus.PENDING else "",
                human_duration(s.duration) if s.status is not SourceStatus.PENDING else "",
                Text(note, style="dim"),
            )

        # footer: live counters that keep moving even when nothing changes
        found = sum(s.found for s in items)
        new = sum(s.unique for s in items)
        done = sum(1 for s in items if s.status in _DONE_STATES)
        skipped = sum(1 for s in items if s.status is SourceStatus.SKIPPED)
        total = len(items)
        elapsed = time.monotonic() - self._start
        if final:
            head = Text("  done", style="bold green")
        else:
            names = ", ".join(s.source for s in running[:3])
            if len(running) > 3:
                names += f" +{len(running) - 3}"
            head = Text(f"  {spin} ", style="cyan") + Text(
                f"{len(running)} running" + (f": {names}" if names else ""), style="cyan"
            )
        footer = Text.assemble(
            head,
            Text("   •   ", style="dim"),
            Text(f"{done}/{total} sources", style="white"),
            Text(f" ({skipped} skipped)", style="dim"),
            Text("   •   ", style="dim"),
            Text(f"{human_int(found)} found", style="green"),
            Text(f" · {human_int(new)} new", style="dim"),
            Text("   •   ", style="dim"),
            Text(_mmss(elapsed), style="bold"),
        )
        return Group(t, Text(""), footer)

    def _plain_line(self, s: SourceStats) -> None:
        prev = self._printed.get(s.source)
        if s.status is SourceStatus.RUNNING:
            return  # avoid progress spam in plain/piped mode
        if prev in _DONE_STATES or prev is SourceStatus.SKIPPED:
            return
        self._printed[s.source] = s.status
        _, sym = _STATUS_STYLE[s.status]
        line = f"  [{sym}] {s.source:<16} {s.status.value:<8}"
        if s.status in _DONE_STATES:
            line += f" {s.found:>6} found {s.unique:>6} new  {human_duration(s.duration):>7}"
        if s.error:
            line += f"  {truncate(s.error, 80)}"
        self.err.print(line, markup=False)

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
        shown = [s for s in rows if s.status in _DONE_STATES] + [
            s for s in rows if s.status not in _DONE_STATES
        ]
        for s in shown:
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
        self.err.rule("[bold]results[/bold]", style="dim")
        self.err.print(t)
        self.err.print()
        line = (
            f"  [bold green]{human_int(counts.get('total', 0))}[/bold green] subdomains"
            f"   •   [bold]{human_int(counts.get('resolved', 0))}[/bold] resolved"
            f"   •   {human_int(counts.get('alive', 0))} alive"
            f"   •   {human_int(counts.get('wildcard', 0))} wildcard-only"
            f"   •   {human_int(counts.get('new_this_run', 0))} new this run"
            f"   •   {human_duration(elapsed)}"
        )
        if counts.get("related"):
            line += f"   •   {human_int(counts['related'])} related"
        self.err.print(line)
        if interrupted:
            self.err.print("  [yellow]interrupted: partial results were written.[/yellow]")
        if out_dir is not None:
            self.err.print(f"  output: [bold]{out_dir}[/bold]")
        self.err.print()

    def print(self, *args: object, **kwargs: object) -> None:
        self.err.print(*args, **kwargs)  # type: ignore[arg-type]
