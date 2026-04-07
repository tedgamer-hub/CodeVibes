from __future__ import annotations

import sys

from .cli import main as cli_main


def main(argv: list[str] | None = None) -> int:
    raw_args = argv if argv is not None else sys.argv[1:]
    return cli_main(["ui", *raw_args])

