"""Tests for the optional Streamlit dashboard; skipped when streamlit is not installed."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest

from attackpath import dashboard
from attackpath.dashboard import app

pytestmark = pytest.mark.dashboard

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "sample_environment.json"


def _run_app(monkeypatch: pytest.MonkeyPatch) -> AppTest:
    monkeypatch.setattr(sys, "argv", ["app.py", "--input", str(FIXTURE)])
    monkeypatch.delenv(app.INPUT_ENV_VAR, raising=False)
    return AppTest.from_file(str(dashboard.APP_PATH), default_timeout=120).run()


def _findings_table(at: AppTest) -> Any:
    tables = [df.value for df in at.dataframe if list(df.value.columns) == app.FINDING_COLUMNS]
    assert len(tables) == 1
    return tables[0]


def test_app_renders_sample_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    at = _run_app(monkeypatch)
    assert not at.exception
    assert len(at.metric) >= 1
    assert at.metric[0].label == "Total findings"
    total = int(at.metric[0].value)
    assert total > 0
    assert any("synthetic fixture, not real account data" in item.value for item in at.info)
    assert any("prioritization heuristics" in item.value for item in at.warning)
    table = _findings_table(at)
    assert len(table) == total
    assert at.selectbox[0].value == table["id"][0]
    assert len(at.download_button) == 3


def test_filters_and_graph_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    at = _run_app(monkeypatch)
    at.sidebar.multiselect[0].select("critical").run()
    assert not at.exception
    table = _findings_table(at)
    assert len(table) > 0
    assert set(table["severity"]) == {"critical"}
    at.toggle[0].set_value(True).run()
    assert not at.exception
    at.sidebar.text_input[0].set_value("no-such-principal").run()
    assert not at.exception
    assert len(_findings_table(at)) == 0


def test_input_path_from_argv_and_environment() -> None:
    assert app.input_path_from(["app.py", "--input", "x.json"], {}) == Path("x.json")
    assert app.input_path_from(["app.py", "--input=y.json"], {}) == Path("y.json")
    assert app.input_path_from(["app.py"], {app.INPUT_ENV_VAR: "z.json"}) == Path("z.json")
    assert app.input_path_from(["app.py", "--input"], {}) is None


def test_launch_returns_1_for_missing_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert dashboard.launch(tmp_path / "missing.json") == 1
    assert "missing.json" in capsys.readouterr().err


def test_launch_names_the_extra_when_streamlit_is_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(dashboard, "streamlit_available", lambda: False)
    assert dashboard.launch(FIXTURE) == 1
    assert 'pip install "aws-cloud-attack-path-analyzer[dashboard]"' in capsys.readouterr().err


def test_launch_runs_streamlit_as_module_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(args: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert dashboard.launch(FIXTURE, port=8765) == 0
    ((args, kwargs),) = calls
    assert args[:4] == [sys.executable, "-m", "streamlit", "run"]
    assert args[4] == str(dashboard.APP_PATH)
    assert args[args.index("--server.port") + 1] == "8765"
    assert args[args.index("--server.headless") + 1] == "true"
    assert args[args.index("--browser.gatherUsageStats") + 1] == "false"
    assert args[args.index("--") + 1 :] == ["--input", str(FIXTURE.resolve())]
    assert kwargs.get("shell", False) is False


def test_launch_treats_keyboard_interrupt_as_clean_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "run", interrupted)
    assert dashboard.launch(FIXTURE) == 0
