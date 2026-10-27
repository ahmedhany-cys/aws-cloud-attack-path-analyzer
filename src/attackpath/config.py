"""Runtime configuration and safety limits.

Limits exist because the analyzer parses untrusted configuration files: a crafted
input must not be able to exhaust memory through a huge document, a deeply nested
JSON tree, or a combinatorial explosion of graph paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from attackpath.models.finding import Severity


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 25 * 1024 * 1024
    max_json_depth: int = 64
    max_policy_files: int = 5000
    max_principals: int = 25_000
    max_resources: int = 50_000
    max_graph_nodes: int = 200_000
    max_graph_edges: int = 2_000_000
    max_paths_per_pair: int = 5
    max_total_paths: int = 10_000
    max_findings: int = 100_000


@dataclass
class AnalysisConfig:
    limits: Limits = field(default_factory=Limits)
    scoring_config_path: Path | None = None
    max_path_depth: int = 4
    min_severity: Severity = Severity.INFORMATIONAL
    enabled_checks: frozenset[str] | None = None

    def is_check_enabled(self, check_id: str) -> bool:
        return self.enabled_checks is None or check_id in self.enabled_checks
