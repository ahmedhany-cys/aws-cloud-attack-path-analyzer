"""Built-in scenario self-check (``python -m attackpath validate``).

Runs the analyzer over the bundled synthetic scenarios and compares the findings
with the expectations recorded in ``data/scenarios/expected.json``. It is the same
mechanism the regression test suite uses, exposed on the command line so that an
installation can be verified without the test tooling.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from attackpath.analysis.engine import analyze
from attackpath.config import AnalysisConfig
from attackpath.exceptions import ConfigError
from attackpath.models.finding import EvidenceKind, Finding, Severity
from attackpath.parser.environment_parser import parse_environment


@dataclass(frozen=True)
class Expectation:
    present: bool
    check_id: str
    principal_contains: str | None = None
    resource_contains: str | None = None
    min_severity: Severity | None = None
    max_severity: Severity | None = None
    evidence_kind: EvidenceKind | None = None
    tag: str | None = None
    note: str = ""

    def describe(self) -> str:
        bits = [self.check_id]
        if self.principal_contains:
            bits.append(f"principal~{self.principal_contains}")
        if self.resource_contains:
            bits.append(f"resource~{self.resource_contains}")
        if self.min_severity:
            bits.append(f">={self.min_severity.value}")
        if self.max_severity:
            bits.append(f"<={self.max_severity.value}")
        if self.evidence_kind:
            bits.append(f"evidence={self.evidence_kind.value}")
        if self.tag:
            bits.append(f"tag={self.tag}")
        return ("present: " if self.present else "absent: ") + " ".join(bits)

    def matches(self, finding: Finding) -> bool:
        if self.check_id != "*" and finding.check_id != self.check_id:
            return False
        if self.principal_contains and self.principal_contains not in (
            finding.affected_principal or ""
        ):
            return False
        if self.resource_contains and self.resource_contains not in (
            finding.affected_resource or ""
        ):
            return False
        if self.min_severity and not finding.severity.at_least(self.min_severity):
            return False
        if self.max_severity and finding.severity.rank > self.max_severity.rank:
            return False
        if self.evidence_kind and finding.evidence_kind is not self.evidence_kind:
            return False
        return not (self.tag and self.tag not in finding.tags)


@dataclass(frozen=True)
class Scenario:
    name: str
    fixture: str
    description: str
    expectations: tuple[Expectation, ...]


@dataclass
class ScenarioResult:
    scenario: Scenario
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    finding_count: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return not self.failed and self.error is None


def scenario_dir() -> Path:
    return Path(str(resources.files("attackpath.data").joinpath("scenarios")))


def load_scenarios(directory: Path | None = None) -> list[Scenario]:
    directory = directory or scenario_dir()
    spec_path = directory / "expected.json"
    try:
        raw = json.loads(spec_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read scenario expectations {spec_path}: {exc}") from exc
    scenarios: list[Scenario] = []
    for entry in raw.get("scenarios", []):
        expectations = tuple(_expectation(e) for e in entry.get("expect", []))
        scenarios.append(
            Scenario(
                name=str(entry["name"]),
                fixture=str(entry["fixture"]),
                description=str(entry.get("description", "")),
                expectations=expectations,
            )
        )
    return scenarios


def _expectation(raw: dict[str, Any]) -> Expectation:
    return Expectation(
        present=bool(raw.get("present", True)),
        check_id=str(raw["check_id"]),
        principal_contains=raw.get("principal_contains"),
        resource_contains=raw.get("resource_contains"),
        min_severity=Severity(raw["min_severity"]) if raw.get("min_severity") else None,
        max_severity=Severity(raw["max_severity"]) if raw.get("max_severity") else None,
        evidence_kind=EvidenceKind(raw["evidence_kind"]) if raw.get("evidence_kind") else None,
        tag=raw.get("tag"),
        note=str(raw.get("note", "")),
    )


def run_scenario(scenario: Scenario, directory: Path | None = None) -> ScenarioResult:
    directory = directory or scenario_dir()
    result = ScenarioResult(scenario)
    try:
        data = json.loads((directory / scenario.fixture).read_text("utf-8"))
        env = parse_environment(data, scenario.fixture)
        analysis = analyze(env, AnalysisConfig())
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.finding_count = len(analysis.findings)
    for expectation in scenario.expectations:
        matched = [f for f in analysis.findings if expectation.matches(f)]
        ok = bool(matched) if expectation.present else not matched
        label = expectation.describe()
        if ok:
            result.passed.append(label)
        else:
            if expectation.present:
                detail = "no matching finding"
            else:
                detail = "unexpected: " + ", ".join(
                    f"{m.id} ({m.severity.value})" for m in matched[:3]
                )
            result.failed.append(f"{label} -> {detail}")
    return result


def run_all(directory: Path | None = None) -> list[ScenarioResult]:
    return [run_scenario(s, directory) for s in load_scenarios(directory)]


def format_results(results: list[ScenarioResult], *, verbose: bool = False) -> str:
    lines: list[str] = []
    total_pass = total_fail = 0
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        lines.append(
            f"[{status}] {r.scenario.name}: {len(r.passed)} expectation(s) met, {len(r.failed)} failed, {r.finding_count} finding(s)"
        )
        if r.error:
            lines.append(f"       error: {r.error}")
        for item in r.failed:
            lines.append(f"       FAILED {item}")
        if verbose:
            for item in r.passed:
                lines.append(f"       ok     {item}")
        total_pass += len(r.passed)
        total_fail += len(r.failed) + (1 if r.error else 0)
    lines.append(
        f"{len(results)} scenario(s): {total_pass} expectation(s) met, {total_fail} failed"
    )
    return "\n".join(lines)
