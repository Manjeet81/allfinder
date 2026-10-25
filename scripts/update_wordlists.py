#!/usr/bin/env python3
"""Standalone downloader for resolvers / wordlists / takeover fingerprints.

Equivalent to ``allfinder update``; handy in CI or cron without installing
the console script.  Run with ``-I`` is not required (it only writes data).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from allfinder.core.config import load_config
from allfinder.core.wordlists import DATA_FILES, update_all


def main() -> int:
    parser = argparse.ArgumentParser(description="Download allfinder data files.")
    parser.add_argument("--config", default=None, help="config file path")
    parser.add_argument("--force", action="store_true", help="re-download even if fresh")
    parser.add_argument("--large", action="store_true", help="also fetch the 9M wordlist")
    parser.add_argument("names", nargs="*", choices=[*DATA_FILES, []], help="specific files")
    args = parser.parse_args()
    cfg = load_config(args.config)
    from rich.console import Console

    results = asyncio.run(
        update_all(
            cfg,
            names=args.names or None,
            force=args.force,
            include_large=args.large,
            console=Console(stderr=True),
        )
    )
    missing = [n for n, p in results.items() if p is None]
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
