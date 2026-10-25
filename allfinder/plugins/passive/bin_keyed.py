"""Binary wrappers that need an API key: chaos, shosubgo, github/gitlab-subdomains, haktrails."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from allfinder.core.context import RunContext
from allfinder.core.models import SourceKind, Target
from allfinder.plugins.base import SkipPlugin
from allfinder.plugins.passive.bin_common import LineBinaryPlugin


class ChaosBin(LineBinaryPlugin):
    name = "chaos-bin"
    kind = SourceKind.PASSIVE
    description = "projectdiscovery chaos client (binary; native 'chaos' preferred)"
    binary = "chaos"
    requires = {"api_keys": ["chaos"]}
    default_timeout = 300
    weight = 5
    tags = ("binaries", "keyed")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        key = ctx.keys.get("chaos")
        if not key:
            raise SkipPlugin("no API key: chaos")
        return ["-d", target.root, "-silent", "-key", key]


class Shosubgo(LineBinaryPlugin):
    name = "shosubgo"
    kind = SourceKind.PASSIVE
    description = "shosubgo (Shodan DNS, binary)"
    binary = "shosubgo"
    requires = {"api_keys": ["shodan"]}
    default_timeout = 300
    weight = 4
    tags = ("binaries", "keyed")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        key = ctx.keys.get("shodan")
        if not key:
            raise SkipPlugin("no API key: shodan")
        return ["-d", target.root, "-s", key]


class GithubSubdomains(LineBinaryPlugin):
    name = "github-subdomains"
    kind = SourceKind.PASSIVE
    description = "gwen001 github-subdomains (binary)"
    binary = "github-subdomains"
    requires = {"api_keys": ["github"]}
    default_timeout = 900
    weight = 3
    tags = ("binaries", "keyed", "code")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        tokens = ctx.keys.all("github")
        if not tokens:
            raise SkipPlugin("no API key: github")
        if len(tokens) > 1:
            tf = Path(ctx.tmpdir) / ".github_tokens"
            tf.write_text("\n".join(tokens) + "\n", encoding="utf-8")
            return ["-d", target.root, "-raw", "-e", "-tf", str(tf)]
        return ["-d", target.root, "-raw", "-e", "-t", tokens[0]]


class GitlabSubdomains(LineBinaryPlugin):
    name = "gitlab-subdomains"
    kind = SourceKind.PASSIVE
    description = "gwen001 gitlab-subdomains (binary)"
    binary = "gitlab-subdomains"
    requires = {"api_keys": ["gitlab"]}
    default_timeout = 900
    weight = 3
    tags = ("binaries", "keyed", "code")

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        token = ctx.keys.get("gitlab")
        if not token:
            raise SkipPlugin("no API key: gitlab")
        return ["-d", target.root, "-t", token]


class Haktrails(LineBinaryPlugin):
    name = "haktrails"
    kind = SourceKind.PASSIVE
    description = "hakluke haktrails subdomains (SecurityTrails via binary)"
    binary = "haktrails"
    default_timeout = 300
    weight = 3
    stdin_target = True
    tags = ("binaries", "keyed")

    def check(self, ctx: RunContext) -> str | None:
        reason = super().check(ctx)
        if reason:
            return reason
        cfg = Path.home() / ".config" / "haktools" / "haktrails-config.yml"
        if not cfg.is_file() and not ctx.keys.has("securitytrails"):
            return f"haktrails config missing ({cfg}) and no securitytrails key"
        return None

    def args(self, ctx: RunContext, target: Target) -> Sequence[str]:
        cfg = Path.home() / ".config" / "haktools" / "haktrails-config.yml"
        if not cfg.is_file():
            key = ctx.keys.get("securitytrails")
            if key:
                cfg.parent.mkdir(parents=True, exist_ok=True)
                cfg.write_text(f"securitytrails:\n  key: {key}\n", encoding="utf-8")
                ctx.log.info("haktrails: wrote %s from allfinder keys", cfg)
        return ["subdomains"]
