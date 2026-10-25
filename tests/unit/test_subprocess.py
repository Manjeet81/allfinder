import sys

import pytest

from allfinder.utils.subprocess import BinaryError, ProcResult, run_capture, run_stream

PY = sys.executable


async def test_stream_lines_and_stderr() -> None:
    code = "import sys; print('a'); print('b'); print('err', file=sys.stderr); print('')"
    res = ProcResult()
    lines = [ln async for ln in run_stream([PY, "-c", code], result=res)]
    assert lines == ["a", "b"]
    assert res.returncode == 0
    assert res.lines == 2
    assert "err" in res.stderr_text


async def test_stdin_data() -> None:
    code = "import sys; [print(l.strip().upper()) for l in sys.stdin]"
    lines, res = await run_capture([PY, "-c", code], stdin_data="x\ny\n")
    assert lines == ["X", "Y"]


async def test_nonzero_exit_raises_after_lines() -> None:
    code = "print('partial'); raise SystemExit(3)"
    got = []
    with pytest.raises(BinaryError) as ei:
        async for ln in run_stream([PY, "-c", code]):
            got.append(ln)
    assert got == ["partial"]
    assert ei.value.returncode == 3
    # check=False swallows
    lines, res = await run_capture([PY, "-c", code], check=False)
    assert lines == ["partial"] and res.returncode == 3


async def test_timeout_kills() -> None:
    code = "import time,sys; print('one', flush=True); time.sleep(30); print('never')"
    got = []
    with pytest.raises(TimeoutError):
        async for ln in run_stream([PY, "-c", code], timeout=1.0):
            got.append(ln)
    assert got == ["one"]
