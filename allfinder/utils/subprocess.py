"""Async subprocess helpers: stream stdout lines, enforce timeouts, kill trees.

Windows-safe: process trees are killed via ``psutil`` so wrapped Go tools do
not linger after Ctrl+C or a timeout.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import psutil

log = logging.getLogger("allfinder.subprocess")


class BinaryError(RuntimeError):
    """Raised when a wrapped tool exits non-zero (after streaming what it had)."""

    def __init__(self, cmd: Sequence[str], returncode: int | None, stderr_tail: str) -> None:
        self.cmd = list(cmd)
        self.returncode = returncode
        self.stderr_tail = stderr_tail
        name = Path(cmd[0]).name if cmd else "?"
        msg = f"{name} exited with {returncode}"
        if stderr_tail:
            msg += f": {stderr_tail.strip().splitlines()[-1][:200]}"
        super().__init__(msg)


def kill_tree(pid: int, *, include_parent: bool = True, timeout: float = 3.0) -> None:
    """Terminate *pid* and all of its children (best effort, never raises)."""
    try:
        parent = psutil.Process(pid)
    except psutil.Error:
        return
    procs: list[psutil.Process] = []
    with contextlib.suppress(psutil.Error):
        procs = parent.children(recursive=True)
    if include_parent:
        procs.append(parent)
    for p in procs:
        with contextlib.suppress(psutil.Error):
            p.terminate()
    _, alive = psutil.wait_procs(procs, timeout=timeout)
    for p in alive:
        with contextlib.suppress(psutil.Error):
            p.kill()


@dataclass(slots=True)
class ProcResult:
    returncode: int | None = None
    stderr: list[str] = field(default_factory=list)
    lines: int = 0
    timed_out: bool = False

    @property
    def stderr_text(self) -> str:
        return "\n".join(self.stderr)


async def _pump_stderr(
    stream: asyncio.StreamReader | None, sink: list[str], limit: int = 200
) -> None:
    if stream is None:
        return
    while True:
        try:
            raw = await stream.readline()
        except (asyncio.LimitOverrunError, ValueError):
            continue
        if not raw:
            break
        text = raw.decode("utf-8", "replace").rstrip("\r\n")
        if text:
            sink.append(text)
            if len(sink) > limit:
                del sink[0]


async def run_stream(
    cmd: Sequence[str],
    *,
    timeout: float | None = None,
    stdin_data: str | bytes | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    result: ProcResult | None = None,
    check: bool = True,
) -> AsyncIterator[str]:
    """Run *cmd* and yield stdout lines as they arrive.

    * ``timeout`` kills the process tree and raises ``TimeoutError`` (lines
      yielded so far are kept by the caller).
    * ``stdin_data`` is written to the child's stdin then closed.
    * stderr is collected into ``result.stderr`` (last 200 lines).
    * on non-zero exit ``BinaryError`` is raised *after* all lines were yielded
      unless ``check=False``.
    """
    res = result if result is not None else ProcResult()
    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=full_env,
        cwd=str(cwd) if cwd else None,
        limit=4 * 1024 * 1024,
    )
    log.debug("spawned pid=%s cmd=%s", proc.pid, " ".join(cmd))
    err_task = asyncio.create_task(_pump_stderr(proc.stderr, res.stderr))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout if timeout else None

    async def _feed_stdin() -> None:
        if proc.stdin is None or stdin_data is None:
            return
        data = stdin_data.encode() if isinstance(stdin_data, str) else stdin_data
        try:
            proc.stdin.write(data)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                proc.stdin.close()

    stdin_task = asyncio.create_task(_feed_stdin())
    try:
        assert proc.stdout is not None
        while True:
            remaining = None if deadline is None else deadline - loop.time()
            if remaining is not None and remaining <= 0:
                res.timed_out = True
                raise TimeoutError(f"{Path(cmd[0]).name} timed out after {timeout}s")
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), remaining)
            except TimeoutError:
                res.timed_out = True
                raise TimeoutError(f"{Path(cmd[0]).name} timed out after {timeout}s") from None
            except (asyncio.LimitOverrunError, ValueError):
                continue
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line:
                res.lines += 1
                yield line
        await asyncio.wait_for(proc.wait(), 30)
        res.returncode = proc.returncode
        with contextlib.suppress(Exception):
            await asyncio.wait_for(err_task, 5)
        if check and proc.returncode not in (0, None):
            raise BinaryError(cmd, proc.returncode, res.stderr_text)
    finally:
        stdin_task.cancel()
        if proc.returncode is None:
            kill_tree(proc.pid)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), 5)
        if not err_task.done():
            err_task.cancel()
            with contextlib.suppress(BaseException):
                await err_task


async def run_capture(
    cmd: Sequence[str],
    *,
    timeout: float | None = None,
    stdin_data: str | bytes | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    check: bool = True,
) -> tuple[list[str], ProcResult]:
    """Convenience: run and collect all stdout lines."""
    res = ProcResult()
    lines: list[str] = []
    async for line in run_stream(
        cmd, timeout=timeout, stdin_data=stdin_data, env=env, cwd=cwd, result=res, check=check
    ):
        lines.append(line)
    return lines, res


def python_executable() -> str:
    return sys.executable
