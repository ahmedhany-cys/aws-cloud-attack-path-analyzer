"""Finding and report models.

Every finding carries the same structure so that JSON, Markdown and HTML outputs,
the dashboard and the regression tests all consume one shape. The ``evidence_kind``
field is the honesty mechanism of the tool: it states whether a finding is a
directly observed configuration fact, an inference from several facts, a
hypothesis that needs preconditions outside the snapshot, or something the
evaluator could not decide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attackpath.models.serialize import to_jsonable


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    @classmethod
    def ordered(cls) -> list[Severity]:
        return sorted(cls, key=lambda s: -s.rank)


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceKind(str, Enum):
    """How much of the finding rests on the snapshot itself."""

    OBSERVED = "observed"  # a direct configuration fact
    INFERRED = "inferred"  # follows from combining several configuration facts
    HYPOTHETICAL = "hypothetical"  # needs assumptions beyond the snapshot
    INDETERMINATE = "indeterminate"  # the evaluator could not decide


class Category(str, Enum):
    EXCESSIVE_PERMISSIONS = "excessive-permissions"
    TRUST_RELATIONSHIP = "trust-relationship"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    RESOURCE_EXPOSURE = "resource-exposure"
    SENSITIVE_ACCESS = "sensitive-data-access"
    ATTACK_PATH = "attack-path"
    EVALUATION_LIMITATION = "evaluation-limitation"
    COVERAGE = "inventory-coverage"


@dataclass(frozen=True)
class Evidence:
    """One piece of supporting evidence, pointing at the snapshot."""

    source: str
    detail: str
    statement: dict[str, Any] | None = None


@dataclass(frozen=True)
class PathStep:
    source: str
    edge: str
    target: str
    description: str
    confidence: Confidence
    evidence: tuple[Evidence, ...] = ()
    preconditions: tuple[str, ...] = ()


@dataclass(frozen=True)
class FactorScore:
    value: float
    weight: float
    rationale: str


@dataclass(frozen=True)
class ScoreBreakdown:
    factors: dict[str, FactorScore]
    base_score: float
    confidence_multiplier: float
    precondition_multiplier: float
    raw_score: float
    final_score: float
    cap_applied: str | None = None


@dataclass(frozen=True)
class Remediation:
    summary: str
    steps: tuple[str, ...] = ()
    suggested_policy: dict[str, Any] | None = None
    policy_assumptions: tuple[str, ...] = ()
    verification_steps: tuple[str, ...] = ()


@dataclass
class Finding:
    id: str
    check_id: str
    category: Category
    title: str
    severity: Severity
    confidence: Confidence
    evidence_kind: EvidenceKind
    description: str
    impact: str
    remediation: Remediation
    affected_principal: str | None = None
    affected_resource: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    attack_path: list[PathStep] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    score: float = 0.0
    score_breakdown: ScoreBreakdown | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = to_jsonable(self)
        if not isinstance(data, dict):  # pragma: no cover - structural invariant
            raise TypeError("dataclass serialization must produce a mapping")
        return data


@dataclass
class GraphSummary:
    node_count: int = 0
    edge_count: int = 0
    nodes_by_type: dict[str, int] = field(default_factory=dict)
    edges_by_type: dict[str, int] = field(default_factory=dict)
    paths_found: int = 0
    paths_truncated: bool = False


@dataclass
class AnalysisReport:
    """Everything the reporting layer needs, independent of output format."""

    tool_version: str
    schema_version: str
    generated_at: str
    input_description: str
    account_id: str
    environment_name: str
    synthetic: bool
    source: str
    environment_summary: dict[str, int]
    coverage: dict[str, Any]
    findings: list[Finding]
    graph: GraphSummary
    limitations: list[str] = field(default_factory=list)
    scoring: dict[str, Any] = field(default_factory=dict)
    analysis_seconds: float | None = None

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity.ordered()}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category.value] = counts.get(f.category.value, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict[str, Any]:
        data = to_jsonable(self)
        if not isinstance(data, dict):  # pragma: no cover - structural invariant
            raise TypeError("dataclass serialization must produce a mapping")
        data["summary"] = {
            "total_findings": len(self.findings),
            "by_severity": self.counts_by_severity(),
            "by_category": self.counts_by_category(),
        }
        return data
