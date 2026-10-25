"""Shared base for wrappers whose stdout is one hostname/URL per line."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import ClassVar

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, Target
from allfinder.plugins.base import BinaryPlugin
from allfinder.utils.subprocess import BinaryError, ProcResult


class LineBinaryPlugin(BinaryPlugin):
    """Run ``<binary> <args>`` and turn every stdout line into findings.

    Subclasses implement :meth:`args`; ``extract=True`` applies the hostname
    regex to each line (for tools that print URLs or decorated output) while
    ``extract=False`` treats each line as a bare hostname.
    """

    extract: ClassVar[bool] = False
    stdin_target: ClassVar[bool] = False  # feed the domain on stdin instead of args
    tolerate_exit_codes: ClassVar[tuple[int, ...]] = ()

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:  # pragma: no cover
        raise NotImplementedError

    def env(self, ctx: RunContext) -> dict[str, str] | None:
        return None

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        res = ProcResult()
        seen: set[str] = set()
        stdin = target.root + "\n" if self.stdin_target else None
        try:
            async for line in self.lines(
                ctx,
                self.args(ctx, target),
                stdin_data=stdin,
                env=self.env(ctx),
                result=res,
                check=True,
            ):
                for f in self.parse_line(line, target):
                    if f.hostname not in seen:
                        seen.add(f.hostname)
                        yield f
        except BinaryError as exc:
            if exc.returncode in self.tolerate_exit_codes:
                return
            if seen:  # partial output is more useful than an error
                self.log.warning(
                    "%s exited %s after %d results", self.name, exc.returncode, len(seen)
                )
                return
            raise

    def parse_line(self, line: str, target: Target) -> list[Finding]:
        line = line.strip()
        if not line or line.startswith(("[", "#")):
            return []
        if self.extract:
            return list(self.findings_from_text(line, target))
        f = self.finding(line.split()[0])
        return [f] if f else []
