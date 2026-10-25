"""``allfinder`` command line (typer)."""

from __future__ import annotations

import asyncio
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from allfinder import __version__
from allfinder.core import binaries
from allfinder.core.config import (
    Config,
    KeyRing,
    default_config_path,
    example_config_text,
    load_config,
    set_config_value,
)
from allfinder.core.context import RunContext, RunOptions
from allfinder.core.http import make_client
from allfinder.core.logging import setup_logging
from allfinder.core.models import SourceKind
from allfinder.core.normalize import Scope, normalize_hostname
from allfinder.core.registry import UnknownSourceError, get_registry
from allfinder.core.store import Store
from allfinder.plugins.base import BinaryPlugin
from allfinder.utils.text import parse_duration

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="All subdomain finders in one place: passive + active enumeration from the terminal.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
config_app = typer.Typer(no_args_is_help=True, help="Manage ~/.allfinder/config.yaml")
app.add_typer(config_app, name="config")

err = Console(stderr=True, highlight=False)


def _fail(message: str, code: int = 1) -> NoReturn:
    err.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"allfinder {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version", "-V", callback=_version_callback, is_eager=True, help="Show version."
        ),
    ] = False,
) -> None:
    """allfinder: subdomain enumeration that makes the tools feed each other."""


# --------------------------------------------------------------------------- helpers


def _load_config(path: Path | None) -> Config:
    try:
        return load_config(path)
    except (FileNotFoundError, ValueError) as exc:
        _fail(str(exc))


def _collect_roots(domains: list[str] | None, list_file: Path | None) -> list[str]:
    raw: list[str] = []
    for d in domains or []:
        raw.extend(p for p in d.split(",") if p.strip())
    if list_file is not None:
        if str(list_file) == "-":
            raw.extend(sys.stdin.read().split())
        else:
            if not list_file.is_file():
                _fail(f"list file not found: {list_file}")
            raw.extend(list_file.read_text(encoding="utf-8").split())
    roots: list[str] = []
    for r in raw:
        host = normalize_hostname(r, allow_single_label=False)
        if not host:
            _fail(f"invalid domain: {r!r}")
        if host not in roots:
            roots.append(host)
    if not roots:
        _fail("no target: use -d example.com or -l roots.txt")
    return roots


def _store_path(cfg: Config, override: Path | None) -> Path:
    return override or (cfg.data_dir / "allfinder.db")


def _apply_profile(cfg: Config, name: str | None, overrides: dict[str, Any]) -> dict[str, Any]:
    """Merge profile values under explicit CLI flags (flags win)."""
    merged: dict[str, Any] = {}
    if name:
        try:
            merged.update(cfg.profile(name))
        except KeyError as exc:
            _fail(str(exc))
    for k, v in overrides.items():
        if v is not None:
            merged[k] = v
    return merged


# --------------------------------------------------------------------------- enum


@app.command()
def enum(  # noqa: PLR0913 - CLI surface
    domain: Annotated[
        list[str] | None, typer.Option("-d", "--domain", help="Root domain (repeatable, comma ok).")
    ] = None,
    list_file: Annotated[
        Path | None, typer.Option("-l", "--list", help="File with root domains ('-' = stdin).")
    ] = None,
    out_dir: Annotated[Path, typer.Option("-o", "--out-dir", help="Output base directory.")] = Path(
        "out"
    ),
    use: Annotated[
        list[str] | None, typer.Option("--use", help="Only these sources/tags (comma ok).")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="Skip these sources/tags.")
    ] = None,
    active: Annotated[
        bool | None,
        typer.Option(
            "--active/--no-active", help="Run active techniques (authorized targets only)."
        ),
    ] = None,
    probe: Annotated[
        bool | None, typer.Option("--probe/--no-probe", help="HTTP probe + enrichment.")
    ] = None,
    passive_only: Annotated[
        bool, typer.Option("--passive-only", help="Passive sources only, no DNS resolution.")
    ] = False,
    brute: Annotated[
        str | None, typer.Option("--brute", help="none|small|medium|large|custom:<path>")
    ] = None,
    permute: Annotated[
        bool | None, typer.Option("--permute/--no-permute", help="Permutation stage (active).")
    ] = None,
    depth: Annotated[
        int | None, typer.Option("--depth", help="Recursion depth for sub-roots.")
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", help="Sources running at once.")
    ] = None,
    qps: Annotated[int | None, typer.Option("--qps", help="DNS queries per second.")] = None,
    resolvers: Annotated[
        str | None, typer.Option("--resolvers", help="Resolver list file.")
    ] = None,
    trusted_resolvers: Annotated[
        str | None, typer.Option("--trusted-resolvers", help="Trusted resolver list file.")
    ] = None,
    timeout_per_source: Annotated[
        int | None, typer.Option("--timeout-per-source", help="Seconds per source.")
    ] = None,
    max_time: Annotated[
        str | None, typer.Option("--max-time", help="Total time budget, e.g. 2h, 90m.")
    ] = None,
    keep_wildcards: Annotated[
        bool | None, typer.Option("--keep-wildcards", help="Count wildcard-only names as resolved.")
    ] = None,
    include_out_of_scope: Annotated[
        bool | None, typer.Option("--include-out-of-scope", help="Also process related domains.")
    ] = None,
    search_engines: Annotated[
        bool, typer.Option("--search-engines", help="Enable search-engine scraping sources.")
    ] = False,
    silent: Annotated[bool, typer.Option("--silent", help="Only hostnames on stdout.")] = False,
    json_lines: Annotated[
        bool, typer.Option("--json-lines", help="One JSON record per line on stdout.")
    ] = False,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP(S)/SOCKS proxy URL.")] = None,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Plain output, no live table.")
    ] = False,
    keep_tmp: Annotated[bool, typer.Option("--keep-tmp", help="Keep temporary files.")] = False,
    verbose: Annotated[
        int, typer.Option("-v", "--verbose", count=True, help="-v info, -vv debug.")
    ] = 0,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="Config file (default ~/.allfinder/config.yaml)."),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Named profile from config (quick, deep, stealth...)."),
    ] = None,
    resume: Annotated[
        str | None, typer.Option("--resume", help="Run id to resume (see `allfinder diff`).")
    ] = None,
    db: Annotated[Path | None, typer.Option("--db", help="SQLite database path.")] = None,
    skip_resolve: Annotated[bool, typer.Option("--skip-resolve", hidden=True)] = False,
) -> None:
    """Enumerate subdomains: passive sources + resolution (+ --active, --probe)."""
    from allfinder.cli.ui import UI
    from allfinder.core.pipeline import EXIT_USAGE, Pipeline

    cfg = _load_config(config_path)
    roots = _collect_roots(domain, list_file)
    if proxy:
        cfg.http.proxy = proxy
    prof = _apply_profile(
        cfg,
        profile,
        {
            "active": active,
            "probe": probe,
            "brute": brute,
            "permute": permute,
            "depth": depth,
            "concurrency": concurrency,
            "qps": qps,
            "timeout_per_source": timeout_per_source,
            "max_time": max_time,
            "keep_wildcards": keep_wildcards,
            "include_out_of_scope": include_out_of_scope,
            "use": use,
            "exclude": exclude,
            "passive_only": passive_only or None,
            "search_engines": search_engines or None,
        },
    )
    try:
        max_time_s = parse_duration(prof.get("max_time", cfg.limits.max_time))
    except ValueError as exc:
        _fail(str(exc))

    def _split(v: Any) -> list[str]:
        if not v:
            return []
        if isinstance(v, str):
            v = [v]
        out: list[str] = []
        for item in v:
            out.extend(p.strip() for p in str(item).split(",") if p.strip())
        return out

    opts = RunOptions(
        active=bool(prof.get("active", False)),
        probe=bool(prof.get("probe", False)),
        passive_only=bool(prof.get("passive_only", False)),
        brute=str(prof.get("brute", cfg.active.brute)),
        permute=bool(prof.get("permute", cfg.active.permute)),
        depth=int(prof.get("depth", cfg.active.depth)),
        concurrency=int(prof.get("concurrency", cfg.limits.concurrency)),
        qps=int(prof.get("qps", cfg.limits.qps)),
        timeout_per_source=(
            int(prof["timeout_per_source"]) if prof.get("timeout_per_source") is not None else None
        ),
        max_time=max_time_s,
        keep_wildcards=bool(prof.get("keep_wildcards", cfg.results.keep_wildcards)),
        include_out_of_scope=bool(
            prof.get("include_out_of_scope", cfg.results.include_out_of_scope)
        ),
        silent=silent,
        json_lines=json_lines,
        no_color=no_color,
        keep_tmp=keep_tmp,
        verbosity=verbose,
        use=_split(prof.get("use")),
        exclude=_split(prof.get("exclude")),
        resolvers=resolvers or cfg.active.resolvers,
        trusted_resolvers=trusted_resolvers or cfg.active.trusted_resolvers,
        search_engines=bool(prof.get("search_engines", False)),
        resume=resume,
        max_permutations=cfg.active.max_permutations,
        recursion_min_children=cfg.active.recursion_min_children,
        max_new_per_round=cfg.active.max_new_per_round,
        skip_resolve=skip_resolve or bool(prof.get("passive_only", False)),
    )
    if silent and json_lines:
        _fail("--silent and --json-lines are mutually exclusive")

    scope = Scope(roots)
    registry = get_registry()
    try:  # validate --use/--exclude early for a clean usage error
        registry.select(use=opts.use or None, exclude=opts.exclude)
    except UnknownSourceError as exc:
        _fail(str(exc), EXIT_USAGE)

    store = Store(_store_path(cfg, db))
    run_dir = _prepare_out_dir(out_dir, roots, store, resume)
    run = store.start_run(
        roots,
        args=opts.to_dict(),
        version=__version__,
        out_dir=run_dir,
        run_id=resume,
    )
    keys = KeyRing(cfg.keys)
    setup_logging(verbose, run_dir / "run.log", redact=keys.redact, console=verbose > 0)
    ui = UI(silent=silent, json_lines=json_lines, no_color=no_color)
    mode = "passive" if not opts.active else "passive+active"
    if not opts.skip_resolve:
        mode += "+resolve"
    if opts.probe:
        mode += "+probe"
    ui.header(roots, mode)
    if opts.active:
        ui.on_log(
            "warning",
            "[!] active mode sends DNS/HTTP traffic to the target: only scan systems you are authorized to test.",
        )

    async def _main() -> int:
        tmpdir = run_dir / "tmp"
        tmpdir.mkdir(parents=True, exist_ok=True)
        async with make_client(cfg.http) as client:
            ctx = RunContext(
                config=cfg,
                options=opts,
                scope=scope,
                keys=keys,
                http=client,
                store=store,
                run=run,
                out_dir=run_dir,
                tmpdir=tmpdir,
                on_stats=ui.on_stats,
                on_log=ui.on_log,
                on_finding=ui.on_finding,
            )
            ui.start()
            try:
                result = await Pipeline(ctx, registry, ui).run()
            finally:
                ui.stop()
        return result.exit_code

    try:
        code = asyncio.run(_main())
    except KeyboardInterrupt:
        code = 130
    finally:
        store.close()
    raise typer.Exit(code)


def _prepare_out_dir(base: Path, roots: list[str], store: Store, resume: str | None) -> Path:
    if resume:
        prev = store.get_run(resume)
        if prev is None:
            _fail(f"unknown run id: {resume}")
        if prev and prev.out_dir and Path(prev.out_dir).is_dir():
            return Path(prev.out_dir)
    name = roots[0] if len(roots) == 1 else f"{roots[0]}+{len(roots) - 1}"
    stamp = datetime.now(UTC).astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = base / name / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


# --------------------------------------------------------------------------- sources


@app.command()
def sources(
    kind: Annotated[str | None, typer.Option("--kind", help="passive | active | enrich")] = None,
    available: Annotated[
        bool,
        typer.Option("--available", help="Only sources that can run now (keys/binaries present)."),
    ] = False,
    tag: Annotated[
        str | None, typer.Option("--tag", help="Filter by tag (free, keyed, ct, binaries, ...).")
    ] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine readable output.")] = False,
) -> None:
    """List every source/technique and whether it can run on this machine."""
    cfg = _load_config(config_path)
    keys = KeyRing(cfg.keys)
    reg = get_registry()
    rows: list[dict[str, Any]] = []
    for cls in reg.classes():
        if kind and cls.kind.value != kind:
            continue
        if tag and tag not in cls.tags:
            continue
        inst = cls()
        missing = inst.missing_requirements(keys, binaries.which)
        if available and missing:
            continue
        impl = "binary" if issubclass(cls, BinaryPlugin) else "native"
        req = cls.requires or {}
        rows.append(
            {
                "name": cls.name,
                "kind": cls.kind.value,
                "impl": impl,
                "requires": sorted(
                    [
                        *(f"bin:{b}" for b in req.get("binaries", [])),
                        *(f"key:{k}" for k in req.get("api_keys", [])),
                    ]
                ),
                "available": not missing,
                "missing": missing,
                "tags": list(cls.tags),
                "description": cls.description,
            }
        )
    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return
    table = Table(box=None, header_style="bold", pad_edge=False)
    for col in ("source", "kind", "impl", "ok", "requires", "tags", "description"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["name"],
            r["kind"],
            r["impl"],
            "[green]yes[/green]" if r["available"] else "[yellow]no[/yellow]",
            ",".join(r["requires"]),
            ",".join(r["tags"]),
            r["description"],
        )
    Console(highlight=False).print(table)
    Console(highlight=False).print(
        f"\n{len(rows)} sources ({sum(1 for r in rows if r['available'])} available)"
    )


# --------------------------------------------------------------------------- doctor


@app.command()
def doctor(
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Check external binaries, API keys, resolvers and wordlists."""
    cfg = _load_config(config_path)
    console = Console(highlight=False)
    console.print(
        f"[bold]allfinder[/bold] v{__version__}  python {platform.python_version()}  {platform.system()} {platform.machine()}"
    )
    console.print(
        f"config: {default_config_path()}  {'(found)' if default_config_path().is_file() else '(not found: allfinder config init)'}"
    )
    console.print(f"data dir: {cfg.data_dir}")

    infos = asyncio.run(binaries.inspect())
    table = Table(
        title="External binaries (optional, each adds sources)",
        box=None,
        header_style="bold",
        pad_edge=False,
    )
    table.add_column("binary")
    table.add_column("found")
    table.add_column("version")
    table.add_column("install")
    for info in infos:
        if info.found:
            status = "[green]yes[/green]"
        elif not info.supported:
            status = "[dim]n/a on this OS[/dim]"
        else:
            status = "[yellow]no[/yellow]"
        table.add_row(info.name, status, info.version or "", "" if info.found else info.hint)
    console.print()
    console.print(table)
    if binaries.IS_WINDOWS:
        console.print(
            "[dim]note: massdns/puredns do not build on Windows; the built-in resolver is used. WSL2 gives faster brute force.[/dim]"
        )

    keys = KeyRing(cfg.keys)
    reg = get_registry()
    providers: set[str] = set()
    for cls in reg.classes():
        providers.update((cls.requires or {}).get("api_keys", []))
    providers.update(cfg.keys.keys())
    kt = Table(title="API keys", box=None, header_style="bold", pad_edge=False)
    kt.add_column("provider")
    kt.add_column("keys")
    kt.add_column("used by")
    for p in sorted(providers):
        users = [cls.name for cls in reg.classes() if p in (cls.requires or {}).get("api_keys", [])]
        n = keys.count(p)
        kt.add_row(p, f"[green]{n}[/green]" if n else "[yellow]0[/yellow]", ",".join(users))
    console.print()
    console.print(kt)

    try:
        from allfinder.core.wordlists import doctor_files
    except ImportError:
        doctor_files = None  # type: ignore[assignment]
    if doctor_files is not None:
        console.print()
        ft = Table(
            title="Data files (allfinder update)", box=None, header_style="bold", pad_edge=False
        )
        ft.add_column("file")
        ft.add_column("status")
        ft.add_column("path")
        for name, ok, path in doctor_files(cfg):
            ft.add_row(name, "[green]ok[/green]" if ok else "[yellow]missing[/yellow]", str(path))
        console.print(ft)

    avail = sum(1 for cls in reg.classes() if not cls().missing_requirements(keys, binaries.which))
    console.print(
        f"\n{avail}/{len(reg.classes())} sources available now (allfinder sources --available)"
    )


# --------------------------------------------------------------------------- diff


@app.command()
def diff(
    domain: Annotated[str, typer.Option("-d", "--domain", help="Root domain.")],
    since: Annotated[
        str | None, typer.Option("--since", help="Baseline run id (default: previous run).")
    ] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
    list_runs: Annotated[
        bool, typer.Option("--runs", help="List runs for the domain and exit.")
    ] = False,
) -> None:
    """Print hostnames that are new since the previous run (or --since <run-id>)."""
    cfg = _load_config(config_path)
    root = normalize_hostname(domain)
    if not root:
        _fail(f"invalid domain: {domain!r}")
    with Store(_store_path(cfg, db)) as store:
        runs = store.runs(root)
        if list_runs:
            for r in runs:
                fin = (
                    r.finished_at.isoformat(timespec="seconds")
                    if r.finished_at
                    else "running/aborted"
                )
                typer.echo(
                    f"{r.id}\t{r.started_at.isoformat(timespec='seconds')}\t{fin}\t{r.out_dir or ''}"
                )
            return
        if not runs:
            _fail(f"no runs for {root}")
        store.load([root])
        if since:
            if store.get_run(since) is None:
                _fail(f"unknown run id: {since}")
            new = store.new_since(since, [root])
        else:
            latest = runs[-1]
            new = store.first_seen_in_run(latest.id, [root])
            err.print(f"[dim]new in run {latest.id} ({len(runs)} runs total)[/dim]")
        for h in new:
            typer.echo(h)


# --------------------------------------------------------------------------- config


@config_app.command("init")
def config_init(
    path: Annotated[
        Path | None,
        typer.Option("--path", help="Where to write (default ~/.allfinder/config.yaml)."),
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write an example config file."""
    p = path or default_config_path()
    if p.exists() and not force:
        _fail(f"{p} exists (use --force to overwrite)")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(example_config_text(), encoding="utf-8")
    typer.echo(f"wrote {p}")


@config_app.command("show")
def config_show(
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    reveal: Annotated[bool, typer.Option("--reveal", help="Show API keys in clear.")] = False,
) -> None:
    """Print the effective configuration (keys redacted unless --reveal)."""
    cfg = _load_config(config_path)
    data = cfg.model_dump(mode="json")
    if not reveal:
        data["keys"] = {
            k: [f"{v[:3]}***" if len(v) > 6 else "***" for v in vals]
            for k, vals in cfg.keys.items()
        }
    import yaml

    typer.echo(yaml.safe_dump(data, sort_keys=False))


@config_app.command("set")
def config_set(
    assignment: Annotated[str, typer.Argument(help="dotted.key=value, e.g. keys.shodan=abc,def")],
    path: Annotated[Path | None, typer.Option("--path")] = None,
) -> None:
    """Set one value in the config file."""
    if "=" not in assignment:
        _fail("expected key=value")
    key, value = assignment.split("=", 1)
    p = path or default_config_path()
    set_config_value(p, key.strip(), value.strip())
    shown = "***" if key.strip().startswith("keys.") else value.strip()
    typer.echo(f"{p}: {key.strip()} = {shown}")


# --------------------------------------------------------------------------- update


@app.command()
def update(
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Re-download even if files are fresh.")
    ] = False,
) -> None:
    """Download/refresh resolvers, wordlists and takeover fingerprints."""
    cfg = _load_config(config_path)
    try:
        from allfinder.core.wordlists import update_all
    except ImportError:
        _fail("update is not available in this build")
    asyncio.run(update_all(cfg, force=force, console=Console(stderr=True)))


def main() -> None:  # console_scripts entry point helper
    app()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["app", "main", "SourceKind"]
