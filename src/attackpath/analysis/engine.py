"""Orchestrates evaluator, graph construction, path search and the checks."""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from attackpath import __version__
from attackpath.analysis.checks import ALL_CHECKS
from attackpath.analysis.context import AnalysisContext
from attackpath.config import AnalysisConfig
from attackpath.exceptions import LimitExceededError
from attackpath.graph.builder import build_graph
from attackpath.graph.model import SOURCE_NODE_TYPES, AttackGraph
from attackpath.graph.paths import PathSearchResult, find_attack_paths
from attackpath.iam.evaluator import LimitationLog, PolicyEvaluator
from attackpath.models.environment import Environment
from attackpath.models.finding import AnalysisReport, Finding
from attackpath.scoring.model import Scorer, load_scoring_config

REPORT_SCHEMA_VERSION = "1.0"


@dataclass
class AnalysisResult:
    environment: Environment
    graph: AttackGraph
    paths: PathSearchResult
    findings: list[Finding]
    evaluator: PolicyEvaluator
    limitations: LimitationLog
    scorer: Scorer
    mode: str
    warnings: list[str] = field(default_factory=list)
    seconds: float = 0.0
    truncated_findings: bool = False

    def limitation_notes(self) -> list[str]:
        notes: list[str] = []
        if self.paths.truncated:
            notes.append(
                "path enumeration hit a configured limit; some paths with the same endpoints were not enumerated"
            )
        if self.truncated_findings:
            notes.append(
                "the number of findings exceeded the configured limit; lowest-scored findings were dropped"
            )
        for kind, detail, count in self.limitations.entries():
            if kind in ("unresolved-policy", "unresolved-boundary"):
                notes.append(f"{kind}: {detail} ({count} reference(s))")
        return notes


def analyze(
    env: Environment,
    config: AnalysisConfig | None = None,
    *,
    mode: str = "environment",
    input_warnings: Iterable[str] = (),
) -> AnalysisResult:
    """Run the full offline analysis over ``env``. Never performs network calls."""
    started = time.perf_counter()
    config = config or AnalysisConfig()
    limitations = LimitationLog()
    evaluator = PolicyEvaluator(env, limitations)
    graph = build_graph(env, evaluator, config)
    sources = sorted(n.id for n in graph.nodes.values() if n.type in SOURCE_NODE_TYPES)
    paths = find_attack_paths(
        graph,
        sources,
        max_depth=config.max_path_depth,
        max_paths_per_pair=config.limits.max_paths_per_pair,
        max_total_paths=config.limits.max_total_paths,
    )
    scorer = Scorer(load_scoring_config(config.scoring_config_path))
    ctx = AnalysisContext(env, evaluator, graph, paths, config, scorer, mode)

    findings: list[Finding] = []
    for _name, check in ALL_CHECKS:
        findings.extend(check(ctx))

    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.id, finding)
    ordered = sorted(unique.values(), key=lambda f: (-f.severity.rank, -f.score, f.id))
    ordered = [f for f in ordered if f.severity.at_least(config.min_severity)]
    truncated = False
    if len(ordered) > config.limits.max_findings:
        ordered = ordered[: config.limits.max_findings]
        truncated = True
    return AnalysisResult(
        environment=env,
        graph=graph,
        paths=paths,
        findings=ordered,
        evaluator=evaluator,
        limitations=limitations,
        scorer=scorer,
        mode=mode,
        warnings=list(input_warnings),
        seconds=time.perf_counter() - started,
        truncated_findings=truncated,
    )


def build_report(result: AnalysisResult, input_description: str) -> AnalysisReport:
    env = result.environment
    coverage = {
        "services": {
            name: {"status": entry.status.value, "notes": list(entry.notes)}
            for name, entry in sorted(env.coverage.services.items())
        },
        "notes": list(env.coverage.notes),
        "complete": env.coverage.is_complete,
    }
    limitations = result.limitation_notes()
    if result.mode == "policy-files":
        limitations.insert(
            0,
            "policy-only mode: documents were analyzed as standalone policies attached to synthetic "
            "roles; trust relationships, resources and attachments are unknown",
        )
    return AnalysisReport(
        tool_version=__version__,
        schema_version=REPORT_SCHEMA_VERSION,
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        input_description=input_description,
        account_id=env.account_id,
        environment_name=env.metadata.name,
        synthetic=env.metadata.synthetic,
        source=env.metadata.source,
        environment_summary=env.summary(),
        coverage=coverage,
        findings=result.findings,
        graph=result.graph.summary(len(result.paths.paths), result.paths.truncated),
        limitations=limitations + result.warnings,
        scoring=result.scorer.config.to_dict(),
        analysis_seconds=round(result.seconds, 4),
    )


__all__ = ["AnalysisResult", "LimitExceededError", "analyze", "build_report"]
