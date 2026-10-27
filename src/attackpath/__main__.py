"""Allow ``python -m attackpath`` to invoke the command-line interface."""

from __future__ import annotations

import sys

from attackpath.cli import main

if __name__ == "__main__":
    sys.exit(main())
