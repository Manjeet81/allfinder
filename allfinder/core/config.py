"""Configuration: YAML file + ``ALLFINDER_*`` environment overrides + key ring.

Precedence (lowest to highest): built-in defaults -> ``config.yaml`` ->
environment variables -> CLI flags (applied by the CLI layer).
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from allfinder import __version__

ENV_PREFIX = "ALLFINDER_"


def default_data_dir() -> Path:
    home = os.environ.get("ALLFINDER_HOME")
    return Path(home) if home else Path.home() / ".allfinder"


def default_config_path() -> Path:
    return default_data_dir() / "config.yaml"


# --------------------------------------------------------------------------- sections


class Limits(BaseModel):
    model_config = ConfigDict(extra="ignore")

    concurrency: int = 20
    qps: int = 500
    timeout_per_source: int = 60
    max_time: str | None = None


class ActiveConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    brute: str = "none"  # none | small | medium | large | custom:<path>
    permute: bool = True
    max_permutations: int = 200_000
    depth: int = 1
    resolvers: str | None = None
    trusted_resolvers: str | None = None
    recursion_min_children: int = 3
    max_new_per_round: int = 50_000


class ResultsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    keep_wildcards: bool = False
    include_out_of_scope: bool = False
    min_sources: int = 1


class SourcesConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    disabled: list[str] = Field(default_factory=list)
    timeouts: dict[str, int] = Field(default_factory=dict)


class HttpConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    proxy: str | None = None
    user_agent: str = f"allfinder/{__version__}"
    retries: int = 2
    backoff: float = 1.0  # seconds; doubles per retry
    timeout: float = 30.0
    verify_tls: bool = True


class Config(BaseModel):
    model_config = ConfigDict(extra="ignore")

    keys: dict[str, list[str]] = Field(default_factory=dict)
    limits: Limits = Field(default_factory=Limits)
    active: ActiveConfig = Field(default_factory=ActiveConfig)
    results: ResultsConfig = Field(default_factory=ResultsConfig)
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    profiles: dict[str, dict[str, Any]] = Field(default_factory=dict)
    http: HttpConfig = Field(default_factory=HttpConfig)
    data_dir: Path = Field(default_factory=default_data_dir)
    subfinder_provider_config: str = "auto"

    @field_validator("keys", mode="before")
    @classmethod
    def _coerce_keys(cls, value: Any) -> dict[str, list[str]]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ValueError("keys must be a mapping of provider -> list of keys")
        out: dict[str, list[str]] = {}
        for provider, keys in value.items():
            out[str(provider).lower()] = _as_key_list(keys)
        return out

    @field_validator("profiles", mode="before")
    @classmethod
    def _coerce_profiles(cls, value: Any) -> dict[str, dict[str, Any]]:
        return dict(value or {})

    def profile(self, name: str) -> dict[str, Any]:
        if name not in self.profiles:
            raise KeyError(f"unknown profile {name!r}; known: {sorted(self.profiles)}")
        return dict(self.profiles[name])

    def timeout_for(self, source: str) -> int | None:
        return self.sources.timeouts.get(source)


def _as_key_list(keys: Any) -> list[str]:
    if keys is None:
        return []
    if isinstance(keys, str):
        return [k.strip() for k in keys.split(",") if k.strip()]
    if isinstance(keys, Iterable):
        out: list[str] = []
        for k in keys:
            if k is None:
                continue
            k = str(k).strip()
            if k:
                out.append(k)
        return out
    return [str(keys)]


# --------------------------------------------------------------------------- loading


def _parse_scalar(value: str) -> Any:
    """Parse an env-var string into bool/int/null/list using YAML rules."""
    try:
        parsed = yaml.safe_load(value)
    except yaml.YAMLError:
        return value
    if isinstance(parsed, (dict, list)):
        return parsed
    return parsed


def apply_env_overrides(
    data: dict[str, Any], env: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Apply ``ALLFINDER_<SECTION>__<KEY>=value`` overrides in place and return *data*."""
    env = os.environ if env is None else env
    for name, value in env.items():
        if not name.startswith(ENV_PREFIX) or "__" not in name:
            continue
        rest = name[len(ENV_PREFIX) :].lower()
        section, key = rest.split("__", 1)
        bucket = data.setdefault(section, {})
        if not isinstance(bucket, dict):
            bucket = data[section] = {}
        if section == "keys":
            bucket[key] = _as_key_list(value)
        elif section == "sources" and key == "disabled":
            bucket[key] = [v.strip() for v in value.split(",") if v.strip()]
        else:
            bucket[key] = _parse_scalar(value)
    if (home := env.get("ALLFINDER_HOME")) and "data_dir" not in data:
        data["data_dir"] = home
    return data


def load_config(path: Path | str | None = None, env: Mapping[str, str] | None = None) -> Config:
    """Load the config file (explicit *path* must exist; the default may be absent)."""
    data: dict[str, Any] = {}
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"config file not found: {p}")
        data = _read_yaml(p)
    else:
        p = default_config_path()
        if p.is_file():
            data = _read_yaml(p)
    apply_env_overrides(data, env)
    return Config.model_validate(data)


def _read_yaml(p: Path) -> dict[str, Any]:
    with p.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{p}: top level of config must be a mapping")
    return loaded


def example_config_text() -> str:
    """Return the bundled ``config.example.yaml`` (used by ``config init``)."""
    here = Path(__file__).resolve()
    for candidate in (
        here.parent.parent / "data" / "config.example.yaml",
        here.parent.parent.parent / "config.example.yaml",
    ):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    # minimal fallback if the package was installed without the example
    return yaml.safe_dump(Config().model_dump(mode="json"), sort_keys=False)


def set_config_value(path: Path, dotted_key: str, raw_value: str) -> dict[str, Any]:
    """``allfinder config set keys.shodan=abc`` -> update YAML file in place."""
    data = _read_yaml(path) if path.is_file() else {}
    parts = dotted_key.split(".")
    bucket: dict[str, Any] = data
    for part in parts[:-1]:
        nxt = bucket.get(part)
        if not isinstance(nxt, dict):
            nxt = bucket[part] = {}
        bucket = nxt
    leaf = parts[-1]
    if parts[0] == "keys":
        bucket[leaf] = _as_key_list(raw_value)
    else:
        bucket[leaf] = _parse_scalar(raw_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)
    return data


# --------------------------------------------------------------------------- key ring


class KeyRing:
    """Round-robin API keys per provider with temporary blacklisting.

    Keys are never logged; use :meth:`redact` before writing any text that
    might contain them.
    """

    def __init__(
        self, keys: Mapping[str, Sequence[str]] | None = None, *, cooldown: float = 600
    ) -> None:
        self._keys: dict[str, list[str]] = {}
        for provider, ks in (keys or {}).items():
            lst = _as_key_list(ks)
            if lst:
                self._keys[provider.lower()] = lst
        self._idx: dict[str, int] = {}
        self._bad: dict[str, dict[str, float]] = {}
        self._cooldown = cooldown

    # -- queries -----------------------------------------------------------
    def providers(self) -> list[str]:
        return sorted(self._keys)

    def has(self, provider: str) -> bool:
        return bool(self._keys.get(provider.lower()))

    def all(self, provider: str) -> list[str]:
        return list(self._keys.get(provider.lower(), []))

    def count(self, provider: str) -> int:
        return len(self._keys.get(provider.lower(), []))

    def get(self, provider: str) -> str | None:
        """Next usable key for *provider* (round robin), or ``None``."""
        provider = provider.lower()
        keys = self._keys.get(provider)
        if not keys:
            return None
        bad = self._bad.get(provider, {})
        now = time.monotonic()
        n = len(keys)
        start = self._idx.get(provider, 0)
        for offset in range(n):
            i = (start + offset) % n
            key = keys[i]
            until = bad.get(key)
            if until is None or until <= now:
                bad.pop(key, None)
                self._idx[provider] = (i + 1) % n
                return key
        # everything is cooling down: return the one that expires first
        key = min(keys, key=lambda k: bad.get(k, 0.0))
        self._idx[provider] = (keys.index(key) + 1) % n
        return key

    def mark_bad(self, provider: str, key: str, cooldown: float | None = None) -> None:
        """Blacklist *key* for a while (called on 401/403/429)."""
        provider = provider.lower()
        if key not in self._keys.get(provider, []):
            return
        self._bad.setdefault(provider, {})[key] = time.monotonic() + (
            self._cooldown if cooldown is None else cooldown
        )

    def usable(self, provider: str) -> int:
        provider = provider.lower()
        now = time.monotonic()
        bad = self._bad.get(provider, {})
        return sum(1 for k in self._keys.get(provider, []) if bad.get(k, 0.0) <= now)

    # -- safety --------------------------------------------------------------
    def redact(self, text: str) -> str:
        if not text:
            return text
        for keys in self._keys.values():
            for key in keys:
                for part in _key_parts(key):
                    if len(part) >= 6:
                        text = text.replace(part, "***")
        return text

    def __repr__(self) -> str:
        return f"KeyRing({ {p: len(k) for p, k in self._keys.items()} })"


_KEY_SPLIT_RE = re.compile(r"[:@]")


def _key_parts(key: str) -> list[str]:
    """``id:secret`` style keys -> redact both halves separately too."""
    parts = [key]
    parts.extend(p for p in _KEY_SPLIT_RE.split(key) if p and p != key)
    return parts
