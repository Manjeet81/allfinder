"""Generate a subfinder ``provider-config.yaml`` from allfinder's key ring."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from allfinder.core.context import RunContext

# allfinder provider -> subfinder provider name (None = same)
SUBFINDER_NAMES: dict[str, str] = {
    "virustotal": "virustotal",
    "securitytrails": "securitytrails",
    "shodan": "shodan",
    "censys": "censys",
    "chaos": "chaos",
    "github": "github",
    "fofa": "fofa",
    "zoomeye": "zoomeyeapi",
    "netlas": "netlas",
    "hunter": "hunter",
    "quake": "quake",
    "binaryedge": "binaryedge",
    "fullhunt": "fullhunt",
    "leakix": "leakix",
    "passivetotal": "passivetotal",
    "whoisxml": "whoisxmlapi",
    "c99": "c99",
    "dnsdb": "dnsdb",
    "bevigil": "bevigil",
    "redhunt": "redhuntlabs",
    "dnsdumpster": "dnsdumpster",
    "threatbook": "threatbook",
    "certspotter": "certspotter",
    "urlscan": "urlscan",
    "intelx": "intelx",
    "facebook": "facebook",
    "robtex": "robtex",
    "bufferover": "bufferover",
    "builtwith": "builtwith",
    "digitalyama": "digitalyama",
    "fofa_pro": "fofa",
}


def subfinder_provider_mapping(keys: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for provider, ks in keys.items():
        name = SUBFINDER_NAMES.get(provider.lower())
        if not name or not ks:
            continue
        out.setdefault(name, []).extend(k for k in ks if k)
    return out


def write_subfinder_provider_config(ctx: RunContext, path: Path | None = None) -> Path | None:
    """Write the provider config into the data dir (0600) and return its path.

    Returns ``None`` when no relevant key exists so subfinder uses its own config.
    """
    mapping = subfinder_provider_mapping({p: ctx.keys.all(p) for p in ctx.keys.providers()})
    if not mapping:
        return None
    target = path or (ctx.config.data_dir / "subfinder-provider-config.yaml")
    target.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(mapping, sort_keys=True)
    if target.is_file() and target.read_text(encoding="utf-8") == text:
        return target
    target.write_text(text, encoding="utf-8")
    try:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - Windows ACLs
        pass
    ctx.log.debug("subfinder provider config written: %s (%d providers)", target, len(mapping))
    return target
