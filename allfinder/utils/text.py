"""Small text helpers: duration parsing, number formatting, JSON walking."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([smhd]?)", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int | float | None) -> float | None:
    """``"2h"`` -> 7200, ``"90m"`` -> 5400, ``"1h30m"`` -> 5400, ``120`` -> 120."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = value.strip().lower()
    if not text:
        return None
    pos = 0
    total = 0.0
    for m in _DURATION_RE.finditer(text):
        if m.start() != pos:
            raise ValueError(f"invalid duration: {value!r}")
        total += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    if pos != len(text):
        raise ValueError(f"invalid duration: {value!r}")
    return total


def human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    if seconds < 10:
        return f"{seconds:.1f}s"
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def human_int(n: int) -> str:
    """Thousands separated with a thin space-like regular space: 1532 -> '1 532'."""
    return f"{n:,}".replace(",", " ")


def iter_strings(obj: Any, *, max_depth: int = 50) -> Iterator[str]:
    """Yield every string found anywhere inside a (possibly nested) JSON value."""
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            continue
        if isinstance(cur, str):
            yield cur
        elif isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, (list, tuple, set)):
            stack.extend((v, depth + 1) for v in cur)


def truncate(text: str, width: int = 60) -> str:
    text = text.replace("\n", " ").strip()
    return text if len(text) <= width else text[: width - 1] + "…"


def dig(obj: Any, *path: str | int, default: Any = None) -> Any:
    """Safe nested lookup: ``dig(data, "a", 0, "b")``."""
    cur = obj
    for key in path:
        try:
            cur = cur[key]
        except (KeyError, IndexError, TypeError):
            return default
    return cur
