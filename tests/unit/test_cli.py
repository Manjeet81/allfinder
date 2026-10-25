import json
from pathlib import Path

from typer.testing import CliRunner

from allfinder.cli.main import app

runner = CliRunner()


def _run(args: list[str], tmp_path: Path, env: dict[str, str] | None = None):
    base_env = {"ALLFINDER_HOME": str(tmp_path / "home"), "NO_COLOR": "1", "TERM": "dumb"}
    base_env.update(env or {})
    return runner.invoke(app, args, env=base_env)


def test_version() -> None:
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and "allfinder" in r.output


def test_enum_end_to_end_with_fake_plugin(tmp_path: Path, fake_registry) -> None:
    out = tmp_path / "out"
    r = _run(
        [
            "enum",
            "-d",
            "Example.com",
            "--use",
            "fake",
            "-o",
            str(out),
            "--skip-resolve",
            "--no-color",
        ],
        tmp_path,
    )
    assert r.exit_code == 0, r.output
    run_dirs = list((out / "example.com").iterdir())
    assert len(run_dirs) == 1
    d = run_dirs[0]
    subs = (d / "subdomains.txt").read_text().split()
    assert subs == ["a.example.com", "b.example.com", "c.example.com"]
    assert (d / "related_domains.txt").read_text().split() == ["evil.net"]
    doc = json.loads((d / "results.json").read_text())
    assert doc["counts"]["total"] == 3
    assert doc["sources"][0]["source"] == "fake"
    assert {s["hostname"] for s in doc["subdomains"]} == set(subs)
    assert (d / "results.jsonl").read_text().count("\n") == 3
    assert (d / "results.csv").read_text().startswith("hostname,")
    assert "fake" in (d / "sources.txt").read_text()
    assert (d / "run.log").is_file()
    assert not (d / "tmp").exists()
    assert "Total unique" in r.output


def test_enum_silent_prints_only_hostnames(tmp_path: Path, fake_registry) -> None:
    r = _run(
        [
            "enum",
            "-d",
            "example.com",
            "--use",
            "fake",
            "-o",
            str(tmp_path / "o"),
            "--skip-resolve",
            "--silent",
        ],
        tmp_path,
    )
    assert r.exit_code == 0, r.output
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert sorted(lines) == ["a.example.com", "b.example.com", "c.example.com"]


def test_enum_json_lines(tmp_path: Path, fake_registry) -> None:
    r = _run(
        [
            "enum",
            "-d",
            "example.com",
            "--use",
            "fake",
            "-o",
            str(tmp_path / "o"),
            "--skip-resolve",
            "--json-lines",
        ],
        tmp_path,
    )
    assert r.exit_code == 0, r.output
    recs = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    assert {rec["hostname"] for rec in recs} == {"a.example.com", "b.example.com", "c.example.com"}
    assert all(rec["source"] == "fake" for rec in recs)


def test_enum_exit_code_2_on_source_error(tmp_path: Path, fake_registry) -> None:
    r = _run(
        [
            "enum",
            "-d",
            "example.com",
            "--use",
            "fake,fakefail",
            "-o",
            str(tmp_path / "o"),
            "--skip-resolve",
            "--no-color",
        ],
        tmp_path,
    )
    assert r.exit_code == 2, r.output


def test_enum_usage_errors(tmp_path: Path, fake_registry) -> None:
    assert _run(["enum", "--use", "fake"], tmp_path).exit_code == 1
    assert _run(["enum", "-d", "not a domain"], tmp_path).exit_code == 1
    assert _run(["enum", "-d", "example.com", "--use", "doesnotexist"], tmp_path).exit_code == 1
    assert _run(["enum", "-d", "example.com", "--max-time", "zzz"], tmp_path).exit_code == 1
    assert _run(["enum", "-d", "example.com", "--silent", "--json-lines"], tmp_path).exit_code == 1


def test_enum_list_file_and_diff(tmp_path: Path, fake_registry) -> None:
    lst = tmp_path / "roots.txt"
    lst.write_text("example.com\nexample.org\n")
    out = tmp_path / "o"
    r = _run(
        ["enum", "-l", str(lst), "--use", "fake", "-o", str(out), "--skip-resolve", "--no-color"],
        tmp_path,
    )
    assert r.exit_code == 0, r.output
    assert (out / "example.com+1").is_dir()
    r = _run(["diff", "-d", "example.com", "--runs"], tmp_path)
    assert r.exit_code == 0 and len(r.stdout.strip().splitlines()) == 1
    r = _run(["diff", "-d", "example.com"], tmp_path)
    assert r.exit_code == 0
    assert sorted(r.stdout.split()) == ["a.example.com", "b.example.com", "c.example.com"]
    # second run finds nothing new
    r = _run(
        [
            "enum",
            "-d",
            "example.com",
            "--use",
            "fake",
            "-o",
            str(out),
            "--skip-resolve",
            "--no-color",
        ],
        tmp_path,
    )
    assert r.exit_code == 0
    r = _run(["diff", "-d", "example.com"], tmp_path)
    assert r.stdout.strip() == ""
    assert _run(["diff", "-d", "nothing.com"], tmp_path).exit_code == 1


def test_sources_and_doctor(tmp_path: Path, fake_registry) -> None:
    r = _run(["sources"], tmp_path)
    assert r.exit_code == 0 and "crtsh" in r.output
    r = _run(["sources", "--json", "--tag", "test"], tmp_path)
    rows = json.loads(r.stdout)
    assert {row["name"] for row in rows} >= {"fake", "fakekeyed"}
    keyed = next(row for row in rows if row["name"] == "fakekeyed")
    assert keyed["available"] is False and keyed["missing"] == ["key:fakeprovider"]
    r = _run(["sources", "--available", "--kind", "passive"], tmp_path)
    assert "fakekeyed" not in r.output
    r = _run(["doctor"], tmp_path)
    assert r.exit_code == 0 and "subfinder" in r.output


def test_config_commands(tmp_path: Path) -> None:
    p = tmp_path / "cfg.yaml"
    r = _run(["config", "init", "--path", str(p)], tmp_path)
    assert r.exit_code == 0 and p.is_file()
    assert _run(["config", "init", "--path", str(p)], tmp_path).exit_code == 1
    r = _run(["config", "set", "keys.shodan=abcdefgh,ijklmnop", "--path", str(p)], tmp_path)
    assert r.exit_code == 0 and "abcdefgh" not in r.output
    r = _run(["config", "show", "--config", str(p)], tmp_path)
    assert r.exit_code == 0 and "abc***" in r.output and "abcdefgh" not in r.output
    r = _run(["config", "show", "--config", str(p), "--reveal"], tmp_path)
    assert "abcdefgh" in r.output
    assert _run(["config", "set", "novalue", "--path", str(p)], tmp_path).exit_code == 1
