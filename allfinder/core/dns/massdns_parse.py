"""Parsers for massdns / puredns output formats (JSON ``-o J`` and simple ``-o S``)."""

from __future__ import annotations

import json
from collections.abc import Iterable

from allfinder.core.models import Resolution
from allfinder.core.normalize import normalize_hostname


def parse_massdns_json(lines: Iterable[str]) -> dict[str, Resolution]:
    """``massdns -o J`` ndjson -> hostname -> Resolution (A/AAAA/CNAME merged)."""
    out: dict[str, Resolution] = {}
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        name = normalize_hostname(str(obj.get("name") or ""))
        if not name:
            continue
        res = out.setdefault(name, Resolution(name))
        if obj.get("status") not in (None, "NOERROR"):
            res.error = str(obj.get("status"))
            continue
        answers = (obj.get("data") or {}).get("answers") or []
        for ans in answers:
            if not isinstance(ans, dict):
                continue
            _add(res, str(ans.get("type") or ""), str(ans.get("data") or ""))
    return out


def parse_massdns_simple(lines: Iterable[str]) -> dict[str, Resolution]:
    """``massdns -o S`` / puredns ``--write-massdns`` lines: ``name. TYPE data``."""
    out: dict[str, Resolution] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        name = normalize_hostname(parts[0])
        if not name:
            continue
        res = out.setdefault(name, Resolution(name))
        _add(res, parts[1], parts[2])
    return out


def parse_any(lines: Iterable[str]) -> dict[str, Resolution]:
    buf = list(lines)
    if any(ln.lstrip().startswith("{") for ln in buf[:5]):
        return parse_massdns_json(buf)
    return parse_massdns_simple(buf)


def _add(res: Resolution, rtype: str, data: str) -> None:
    rtype = rtype.upper()
    data = data.strip()
    if not data:
        return
    if rtype == "A" and data not in res.a:
        res.a.append(data)
    elif rtype == "AAAA" and data not in res.aaaa:
        res.aaaa.append(data)
    elif rtype == "CNAME":
        target = normalize_hostname(data)
        if target and target not in res.cname:
            res.cname.append(target)
