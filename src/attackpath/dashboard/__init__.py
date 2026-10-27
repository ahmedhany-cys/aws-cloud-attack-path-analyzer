"""Optional local Streamlit dashboard.

The dashboard is a presentation layer over the same offline analysis the CLI runs:
it reads one snapshot file, never contacts AWS and sends no telemetry. It needs the
``dashboard`` extra; without it :func:`launch` explains how to install it and exits.
"""

from __future__ import annotations

import importlib
import subprocess  # nosec B404
import sys
from pathlib import Path

APP_PATH = Path(__file__).resolve().with_name("app.py")
INSTALL_HINT = 'pip install "aws-cloud-attack-path-analyzer[dashboard]"'


def streamlit_available() -> bool:
    """Return whether streamlit can be imported by the current interpreter."""
    try:
        importlib.import_module("streamlit")
    except ImportError:
        return False
    return True


def launch(input_path: Path, port: int = 8501) -> int:
    """Run the dashboard for ``input_path`` on ``port``; return the process exit code.

    Streamlit executes page scripts through its own runner, so it is started as
    ``python -m streamlit run`` in a subprocess with a fixed argument list and no
    shell. Ctrl-C stops the server and counts as a clean exit.
    """
    if not streamlit_available():
        print(f"error: the dashboard needs streamlit; run {INSTALL_HINT}", file=sys.stderr)
        return 1
    if not input_path.exists():
        print(f"error: {input_path}: no such file or directory", file=sys.stderr)
        return 1
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(APP_PATH),
        "--server.port",
        str(port),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
        "--",
        "--input",
        str(input_path.resolve()),
    ]
    try:
        # Every element of ``command`` is produced above; nothing is shell-interpreted.
        completed = subprocess.run(command, check=False)  # noqa: S603  # nosec B603
    except KeyboardInterrupt:
        return 0
    return completed.returncode


__all__ = ["APP_PATH", "INSTALL_HINT", "launch", "streamlit_available"]
