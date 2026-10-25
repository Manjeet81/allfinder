"""Logging setup: ``run.log`` in the output directory + optional stderr echo."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path

_FMT_FILE = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_FMT_CONSOLE = "%(levelname)s %(name)s: %(message)s"


class RedactFilter(logging.Filter):
    """Scrub API keys from every record before it reaches a handler."""

    def __init__(self, redact: Callable[[str], str]) -> None:
        super().__init__()
        self._redact = redact

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        clean = self._redact(msg)
        if clean != msg:
            record.msg = clean
            record.args = ()
        return True


def setup_logging(
    verbosity: int = 0,
    log_file: Path | None = None,
    *,
    redact: Callable[[str], str] | None = None,
    console: bool | None = None,
) -> logging.Logger:
    """Configure the ``allfinder`` logger tree.

    * file: always DEBUG (if *log_file* given)
    * stderr: WARNING by default, INFO with ``-v``, DEBUG with ``-vv``;
      disabled when *console* is False (the rich UI shows the same information).
    """
    root = logging.getLogger("allfinder")
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    root.propagate = False
    flt = RedactFilter(redact) if redact else None

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(_FMT_FILE))
        if flt:
            fh.addFilter(flt)
        root.addHandler(fh)

    if console is None:
        console = verbosity > 0
    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(
            logging.DEBUG if verbosity >= 2 else logging.INFO if verbosity == 1 else logging.WARNING
        )
        sh.setFormatter(logging.Formatter(_FMT_CONSOLE))
        if flt:
            sh.addFilter(flt)
        root.addHandler(sh)

    # quieten chatty libraries unless -vv
    for noisy in ("httpx", "httpcore", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if verbosity >= 3 else logging.WARNING)
    return root
