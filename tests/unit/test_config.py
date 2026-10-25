from pathlib import Path

import pytest

from allfinder.core.config import (
    Config,
    KeyRing,
    apply_env_overrides,
    load_config,
    set_config_value,
)


def test_defaults() -> None:
    cfg = Config()
    assert cfg.limits.concurrency == 20
    assert cfg.active.brute == "none"
    assert cfg.keys == {}
    assert cfg.http.user_agent.startswith("allfinder/")


def test_keys_coercion() -> None:
    cfg = Config.model_validate({"keys": {"Shodan": "a, b", "vt": ["x", None, " "], "empty": None}})
    assert cfg.keys == {"shodan": ["a", "b"], "vt": ["x"], "empty": []}


def test_env_overrides() -> None:
    data: dict = {"limits": {"concurrency": 5}}
    env = {
        "ALLFINDER_KEYS__SECURITYTRAILS": "k1,k2",
        "ALLFINDER_LIMITS__QPS": "42",
        "ALLFINDER_RESULTS__KEEP_WILDCARDS": "true",
        "ALLFINDER_SOURCES__DISABLED": "amass, searchengines",
        "ALLFINDER_HTTP__PROXY": "http://127.0.0.1:8080",
        "UNRELATED": "x",
        "ALLFINDER_NOSEP": "x",
    }
    apply_env_overrides(data, env)
    cfg = Config.model_validate(data)
    assert cfg.keys["securitytrails"] == ["k1", "k2"]
    assert cfg.limits.qps == 42
    assert cfg.limits.concurrency == 5
    assert cfg.results.keep_wildcards is True
    assert cfg.sources.disabled == ["amass", "searchengines"]
    assert cfg.http.proxy == "http://127.0.0.1:8080"


def test_load_config_file(tmp_path: Path) -> None:
    p = tmp_path / "config.yaml"
    p.write_text(
        "keys:\n  shodan: [abc]\nlimits:\n  concurrency: 3\nprofiles:\n  quick:\n    use: [crtsh]\n",
        encoding="utf-8",
    )
    cfg = load_config(p, env={})
    assert cfg.keys["shodan"] == ["abc"]
    assert cfg.limits.concurrency == 3
    assert cfg.profile("quick") == {"use": ["crtsh"]}
    with pytest.raises(KeyError):
        cfg.profile("nope")
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml", env={})


def test_load_config_default_missing_is_ok(tmp_path: Path) -> None:
    cfg = load_config(None, env={"ALLFINDER_HOME": str(tmp_path)})
    assert cfg.data_dir == tmp_path


def test_set_config_value(tmp_path: Path) -> None:
    p = tmp_path / "sub" / "config.yaml"
    set_config_value(p, "keys.shodan", "a,b")
    set_config_value(p, "limits.qps", "77")
    set_config_value(p, "results.keep_wildcards", "true")
    cfg = load_config(p, env={})
    assert cfg.keys["shodan"] == ["a", "b"]
    assert cfg.limits.qps == 77
    assert cfg.results.keep_wildcards is True


def test_keyring_rotation_and_blacklist() -> None:
    ring = KeyRing({"st": ["k1", "k2", "k3"], "empty": []}, cooldown=1000)
    assert ring.providers() == ["st"]
    assert ring.has("ST") and not ring.has("empty") and not ring.has("nope")
    assert ring.count("st") == 3
    assert [ring.get("st") for _ in range(4)] == ["k1", "k2", "k3", "k1"]
    ring.mark_bad("st", "k2")
    assert ring.usable("st") == 2
    assert [ring.get("st") for _ in range(3)] == ["k3", "k1", "k3"]
    ring.mark_bad("st", "k1")
    ring.mark_bad("st", "k3")
    # all bad -> still returns something (the earliest to expire)
    assert ring.get("st") in {"k1", "k2", "k3"}
    assert ring.get("nope") is None
    ring.mark_bad("st", "not-a-key")  # ignored


def test_keyring_redact() -> None:
    ring = KeyRing({"censys": ["abcdef123:secretsecret"], "x": ["short"]})
    text = "token abcdef123 and secretsecret and abcdef123:secretsecret; short stays"
    out = ring.redact(text)
    assert "abcdef123" not in out and "secretsecret" not in out
    assert "short stays" in out
    assert ring.redact("") == ""
