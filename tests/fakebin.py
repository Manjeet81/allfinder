"""Create fake executables that print fixture output (cross-platform)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from allfinder.core import binaries

_SCRIPT = """
import sys, time
args = sys.argv[1:]
data = sys.stdin.read() if not sys.stdin.isatty() and {read_stdin!r} else ""
sys.stderr.write("fake {name} args=%r stdin=%r\\n" % (args, data[:40]))
out = open({out_path!r}, encoding="utf-8").read()
for line in out.splitlines():
    print(line.replace("{{STDIN}}", data.strip()), flush=True)
    time.sleep({delay})
sys.exit({exit_code})
"""


def make_fake_binary(
    bindir: Path,
    name: str,
    output: str,
    *,
    exit_code: int = 0,
    read_stdin: bool = False,
    delay: float = 0.0,
) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    out_path = bindir / f"{name}.out"
    out_path.write_text(output, encoding="utf-8")
    script = bindir / f"{name}_impl.py"
    script.write_text(
        _SCRIPT.format(
            name=name,
            out_path=str(out_path),
            exit_code=exit_code,
            read_stdin=read_stdin,
            delay=delay,
        ),
        encoding="utf-8",
    )
    if sys.platform.startswith("win"):
        exe = bindir / f"{name}.cmd"
        exe.write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        exe = bindir / name
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        exe.chmod(0o755)
    return exe


class FakeBins:
    def __init__(self, bindir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.bindir = bindir
        self._map: dict[str, str] = {}
        real_which = binaries.which.__wrapped__  # bypass lru_cache

        def fake_which(name: str) -> str | None:
            if name in self._map:
                return self._map[name]
            return real_which(name)

        monkeypatch.setattr(binaries, "which", fake_which)

    def add(self, name: str, output: str, **kw: object) -> Path:
        exe = make_fake_binary(self.bindir, name, output, **kw)  # type: ignore[arg-type]
        self._map[name] = str(exe)
        return exe


@pytest.fixture
def fakebins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeBins:
    return FakeBins(tmp_path / "bin", monkeypatch)


__all__ = ["FakeBins", "fakebins", "make_fake_binary", "os"]
