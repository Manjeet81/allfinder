"""Search-engine dork scraping (low yield, rate limited, behind ``--search-engines``).

Each engine runs ``site:example.com`` and, like Sublist3r, progressively adds
``-site:found.example.com`` exclusions to surface new names.
"""

from __future__ import annotations

import html
from collections.abc import AsyncIterator
from typing import ClassVar
from urllib.parse import unquote

from allfinder.core.context import RunContext
from allfinder.core.models import Finding, SourceKind, Target
from allfinder.plugins.base import HttpPlugin

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class SearchEngine(HttpPlugin):
    kind = SourceKind.PASSIVE
    rate_limit = 0.5
    weight = 1
    default_timeout = 300
    tags = ("searchengines", "free")

    url: ClassVar[str] = ""
    query_param: ClassVar[str] = "q"
    page_param: ClassVar[str] = ""
    page_step: ClassVar[int] = 10
    page_start: ClassVar[int] = 0
    max_pages: ClassVar[int] = 10
    max_rounds: ClassVar[int] = 5  # exclusion-refinement rounds
    blocked_markers: ClassVar[tuple[str, ...]] = ("captcha", "unusual traffic", "automated queries")
    extra_params: ClassVar[dict[str, str]] = {}

    def build_query(self, target: Target, exclude: list[str]) -> str:
        q = f"site:{target.root}"
        for host in exclude[:12]:  # keep the URL short
            q += f" -site:{host}"
        return q

    async def run(self, ctx: RunContext, target: Target) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        exclude: list[str] = []
        headers = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
        for _round in range(self.max_rounds):
            new_round = 0
            for page in range(self.max_pages):
                params: dict[str, object] = {self.query_param: self.build_query(target, exclude)}
                params.update(self.extra_params)
                if self.page_param:
                    params[self.page_param] = self.page_start + page * self.page_step
                resp = await self.get(
                    ctx, self.url, params=params, headers=headers, ok=[403, 429, 503]
                )
                if resp.status_code in (403, 429, 503):
                    self.log.info("%s: blocked (%s)", self.name, resp.status_code)
                    return
                text = html.unescape(unquote(resp.text))
                low = text.lower()
                if any(m in low for m in self.blocked_markers):
                    self.log.info("%s: captcha/anti-bot page", self.name)
                    return
                new_page = 0
                for f in self.findings_from_text(text, target):
                    if f.hostname in seen or f.hostname == target.root:
                        continue
                    seen.add(f.hostname)
                    new_page += 1
                    new_round += 1
                    yield f
                if new_page == 0:
                    break
            if new_round == 0:
                break
            exclude = sorted(seen)[-12:]


class Google(SearchEngine):
    name = "google"
    description = "Google search scraping (site:)"
    url = "https://www.google.com/search"
    page_param = "start"
    extra_params = {"num": "100", "hl": "en", "filter": "0"}
    max_pages = 5


class Bing(SearchEngine):
    name = "bing"
    description = "Bing search scraping (site:)"
    url = "https://www.bing.com/search"
    page_param = "first"
    page_start = 1
    extra_params = {"count": "50"}


class Yahoo(SearchEngine):
    name = "yahoo"
    description = "Yahoo search scraping (site:)"
    url = "https://search.yahoo.com/search"
    query_param = "p"
    page_param = "b"
    page_start = 1


class DuckDuckGo(SearchEngine):
    name = "duckduckgo"
    description = "DuckDuckGo HTML search (site:)"
    url = "https://html.duckduckgo.com/html/"
    max_pages = 1  # HTML endpoint paginates via POST forms; first page only


class Baidu(SearchEngine):
    name = "baidu"
    description = "Baidu search scraping (site:)"
    url = "https://www.baidu.com/s"
    query_param = "wd"
    page_param = "pn"
    extra_params = {"rn": "50"}
    page_step = 50


class Yandex(SearchEngine):
    name = "yandex"
    description = "Yandex search scraping (site:)"
    url = "https://yandex.com/search/"
    query_param = "text"
    page_param = "p"
    page_step = 1
    max_pages = 3


class Ask(SearchEngine):
    name = "ask"
    description = "Ask.com search scraping (site:)"
    url = "https://www.ask.com/web"
    page_param = "page"
    page_start = 1
    page_step = 1
