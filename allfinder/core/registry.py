"""Plugin discovery: built-in packages + ``allfinder.plugins`` entry points.

Selection (``--use`` / ``--exclude``) accepts plugin names, tags (e.g.
``searchengines``, ``binaries``, ``keyed``, ``free``) and kinds
(``passive``, ``active``, ``enrich``).
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Iterable
from importlib.metadata import EntryPoint, entry_points

from allfinder.core.models import SourceKind
from allfinder.plugins.base import Plugin

log = logging.getLogger("allfinder.registry")

BUILTIN_PACKAGES = (
    "allfinder.plugins.passive",
    "allfinder.plugins.active",
    "allfinder.plugins.enrich",
)
ENTRY_POINT_GROUP = "allfinder.plugins"


class UnknownSourceError(ValueError):
    pass


class Registry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[Plugin]] = {}
        self._discovered = False

    # -- registration ------------------------------------------------------
    def register(self, cls: type[Plugin]) -> type[Plugin]:
        if not cls.name:
            raise ValueError(f"{cls.__name__} has no name")
        existing = self._plugins.get(cls.name)
        if existing is not None and existing is not cls:
            log.debug("plugin %s overridden by %s", cls.name, cls.__module__)
        self._plugins[cls.name] = cls
        return cls

    def discover(self, *, force: bool = False) -> Registry:
        if self._discovered and not force:
            return self
        for pkg_name in BUILTIN_PACKAGES:
            try:
                pkg = importlib.import_module(pkg_name)
            except ImportError as exc:  # pragma: no cover
                log.warning("cannot import %s: %s", pkg_name, exc)
                continue
            for mod in pkgutil.iter_modules(pkg.__path__, pkg_name + "."):
                try:
                    module = importlib.import_module(mod.name)
                except Exception as exc:  # a broken plugin must not kill the tool
                    log.warning("plugin module %s failed to import: %s", mod.name, exc)
                    continue
                self._collect(module)
        eps: list[EntryPoint] = []
        try:
            eps = list(entry_points(group=ENTRY_POINT_GROUP))
        except Exception:  # pragma: no cover
            eps = []
        for ep in eps:
            try:
                obj = ep.load()
            except Exception as exc:
                log.warning("entry point %s failed to load: %s", ep.name, exc)
                continue
            if inspect.isclass(obj) and issubclass(obj, Plugin):
                self.register(obj)
            elif inspect.ismodule(obj):
                self._collect(obj)
        self._discovered = True
        return self

    def _collect(self, module: object) -> None:
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Plugin)
                and obj.name
                and not inspect.isabstract(obj)
                and obj.__module__ == getattr(module, "__name__", obj.__module__)
            ):
                self.register(obj)

    # -- queries -----------------------------------------------------------
    def names(self) -> list[str]:
        self.discover()
        return sorted(self._plugins)

    def classes(self) -> list[type[Plugin]]:
        self.discover()
        return [self._plugins[n] for n in sorted(self._plugins)]

    def get(self, name: str) -> Plugin:
        self.discover()
        try:
            return self._plugins[name]()
        except KeyError:
            raise UnknownSourceError(f"unknown source: {name}") from None

    def has(self, name: str) -> bool:
        self.discover()
        return name in self._plugins

    def tags(self) -> set[str]:
        self.discover()
        out: set[str] = set()
        for cls in self._plugins.values():
            out.update(cls.tags)
        return out

    def _expand(self, token: str) -> set[str]:
        """Expand a ``--use``/``--exclude`` token to plugin names."""
        token = token.strip().lower()
        if not token:
            return set()
        if token == "all":
            return set(self._plugins)
        if token in self._plugins:
            return {token}
        if token in {k.value for k in SourceKind}:
            return {n for n, c in self._plugins.items() if c.kind.value == token}
        matches = {n for n, c in self._plugins.items() if token in c.tags}
        if matches:
            return matches
        raise UnknownSourceError(f"unknown source or tag: {token!r} (see: allfinder sources)")

    def names_kind(self, token: str, kind: SourceKind) -> bool:
        """``True`` if the selection *token* resolves to any plugin of *kind*."""
        self.discover()
        try:
            names = self._expand(token)
        except UnknownSourceError:
            return False
        return any(self._plugins[n].kind is kind for n in names)

    def select(
        self,
        *,
        use: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
        kinds: Iterable[SourceKind] | None = None,
        disabled: Iterable[str] | None = None,
    ) -> list[Plugin]:
        """Instantiate the plugins matching the selection, ordered by weight then name."""
        self.discover()
        use_list = _split(use)
        selected: set[str] = set()
        if use_list:
            for tok in use_list:
                selected |= self._expand(tok)
        else:
            selected = set(self._plugins)
        for tok in _split(exclude):
            selected -= self._expand(tok)
        for tok in _split(disabled):
            if not use_list or tok not in use_list:  # explicit --use wins over config.disabled
                try:
                    selected -= self._expand(tok)
                except UnknownSourceError:
                    continue
        if kinds is not None:
            kind_set = set(kinds)
            selected = {n for n in selected if self._plugins[n].kind in kind_set}
        ordered = sorted(selected, key=lambda n: (-self._plugins[n].weight, n))
        return [self._plugins[n]() for n in ordered]


def _split(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or ():
        out.extend(p.strip().lower() for p in str(v).split(",") if p.strip())
    return out


_registry = Registry()


def get_registry() -> Registry:
    return _registry
