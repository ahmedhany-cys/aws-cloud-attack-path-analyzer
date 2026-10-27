"""Regression suite: every bundled scenario must keep producing its expected outcome."""

from __future__ import annotations

import filecmp
import importlib.util
import json

import pytest

from attackpath import selfcheck
from tests.conftest import PACKAGE_SCENARIO_DIR, ROOT, SCENARIO_DIR

SCENARIOS = selfcheck.load_scenarios()


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_scenario_expectations(scenario: selfcheck.Scenario) -> None:
    result = selfcheck.run_scenario(scenario)
    assert result.error is None, result.error
    assert result.failed == [], "\n".join(result.failed)
    assert result.passed, "every scenario must assert something"


def test_scenario_fixtures_are_in_sync_with_the_sample_environment() -> None:
    spec = importlib.util.spec_from_file_location(
        "build_scenarios", ROOT / "scripts" / "build_scenarios.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sample = json.loads(module.SAMPLE.read_text("utf-8"))
    for name, scenario_spec in module.SCENARIOS.items():
        generated = json.dumps(module.build(sample, name, scenario_spec), indent=2) + "\n"
        assert (PACKAGE_SCENARIO_DIR / f"{name}.json").read_text("utf-8") == generated, name
    mirror = filecmp.dircmp(PACKAGE_SCENARIO_DIR, SCENARIO_DIR)
    assert not mirror.left_only and not mirror.right_only and not mirror.diff_files


def test_every_scenario_file_is_referenced() -> None:
    referenced = {s.fixture for s in SCENARIOS}
    on_disk = {p.name for p in PACKAGE_SCENARIO_DIR.glob("*.json")} - {"expected.json"}
    assert referenced == on_disk


def test_expectation_matching_rules() -> None:
    from attackpath.models.finding import Severity

    exp = selfcheck.Expectation(present=True, check_id="*", min_severity=Severity.HIGH)
    assert "present: *" in exp.describe()
    results = selfcheck.run_all()
    text = selfcheck.format_results(results, verbose=True)
    assert "[FAIL]" not in text and "ok     " in text
