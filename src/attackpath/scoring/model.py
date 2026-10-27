"""Risk-scoring model.

The arithmetic is deliberately simple and fully recorded in each finding's
``score_breakdown`` so that a reviewer can audit why a finding received its
severity. See ``docs/scoring.md`` and ``src/attackpath/data/scoring.toml``.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from attackpath.exceptions import ConfigError
from attackpath.models.finding import (
    Confidence,
    EvidenceKind,
    FactorScore,
    ScoreBreakdown,
    Severity,
)

FACTORS: tuple[str, ...] = (
    "permission_breadth",
    "escalation_potential",
    "resource_sensitivity",
    "trust_boundary",
    "exposure",
    "reachability",
)


@dataclass(frozen=True)
class CheckOverride:
    fixed_severity: Severity | None = None
    max_severity: Severity | None = None


@dataclass(frozen=True)
class ScoringConfig:
    weights: dict[str, float]
    evidence_multipliers: dict[EvidenceKind, float]
    confidence_multipliers: dict[Confidence, float]
    precondition_penalty: float
    precondition_floor: float
    thresholds: dict[Severity, float]
    severity_caps: dict[EvidenceKind, Severity] = field(default_factory=dict)
    check_overrides: dict[str, CheckOverride] = field(default_factory=dict)
    source: str = "built-in"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "weights": dict(self.weights),
            "evidence_multipliers": {k.value: v for k, v in self.evidence_multipliers.items()},
            "confidence_multipliers": {k.value: v for k, v in self.confidence_multipliers.items()},
            "precondition_penalty": self.precondition_penalty,
            "precondition_floor": self.precondition_floor,
            "thresholds": {k.value: v for k, v in self.thresholds.items()},
            "severity_caps": {k.value: v.value for k, v in self.severity_caps.items()},
            "check_overrides": {
                k: {
                    "fixed_severity": v.fixed_severity.value if v.fixed_severity else None,
                    "max_severity": v.max_severity.value if v.max_severity else None,
                }
                for k, v in self.check_overrides.items()
            },
        }


def load_scoring_config(path: Path | None = None) -> ScoringConfig:
    """Load the built-in model or a user-supplied TOML override."""
    if path is None:
        text = resources.files("attackpath.data").joinpath("scoring.toml").read_text("utf-8")
        source = "built-in"
    else:
        if not path.is_file():
            raise ConfigError(f"scoring config {path}: not a file")
        if path.stat().st_size > 1_000_000:
            raise ConfigError(f"scoring config {path}: unreasonably large")
        text = path.read_text("utf-8")
        source = str(path)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"scoring config {source}: invalid TOML: {exc}") from exc
    return _config_from_mapping(data, source)


def _config_from_mapping(data: Mapping[str, Any], source: str) -> ScoringConfig:
    weights = _float_map(data.get("weights", {}), "weights", source)
    missing = [f for f in FACTORS if f not in weights]
    if missing:
        raise ConfigError(f"scoring config {source}: weights missing for {', '.join(missing)}")
    unknown = [f for f in weights if f not in FACTORS]
    if unknown:
        raise ConfigError(f"scoring config {source}: unknown weight(s) {', '.join(unknown)}")
    if sum(weights.values()) <= 0:
        raise ConfigError(f"scoring config {source}: weights must sum to a positive number")

    evidence_raw = _float_map(data.get("evidence_multipliers", {}), "evidence_multipliers", source)
    evidence = {kind: evidence_raw.get(kind.value, 1.0) for kind in EvidenceKind}
    confidence_raw = _float_map(
        data.get("confidence_multipliers", {}), "confidence_multipliers", source
    )
    confidence = {c: confidence_raw.get(c.value, 1.0) for c in Confidence}
    for name, mapping in (
        ("evidence_multipliers", evidence),
        ("confidence_multipliers", confidence),
    ):
        for key, value in mapping.items():
            if not 0 <= value <= 1:
                raise ConfigError(f"scoring config {source}: {name}.{key.value} must be in 0..1")

    pre = data.get("preconditions", {})
    if not isinstance(pre, Mapping):
        raise ConfigError(f"scoring config {source}: preconditions must be a table")
    penalty = _float(pre.get("penalty_per_item", 0.08), "preconditions.penalty_per_item", source)
    floor = _float(pre.get("floor", 0.5), "preconditions.floor", source)
    if not 0 <= floor <= 1 or not 0 <= penalty <= 1:
        raise ConfigError(f"scoring config {source}: precondition values must be in 0..1")

    thresholds_raw = _float_map(data.get("thresholds", {}), "thresholds", source)
    thresholds: dict[Severity, float] = {}
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        if sev.value not in thresholds_raw:
            raise ConfigError(f"scoring config {source}: thresholds.{sev.value} is required")
        thresholds[sev] = thresholds_raw[sev.value]
    ordered = [
        thresholds[s] for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    if ordered != sorted(ordered, reverse=True):
        raise ConfigError(f"scoring config {source}: thresholds must decrease from critical to low")

    caps_raw = data.get("severity_caps", {})
    if not isinstance(caps_raw, Mapping):
        raise ConfigError(f"scoring config {source}: severity_caps must be a table")
    caps: dict[EvidenceKind, Severity] = {}
    for key, value in caps_raw.items():
        caps[_evidence_kind(key, source)] = _severity(value, f"severity_caps.{key}", source)

    overrides_raw = data.get("check_overrides", {})
    if not isinstance(overrides_raw, Mapping):
        raise ConfigError(f"scoring config {source}: check_overrides must be a table")
    overrides: dict[str, CheckOverride] = {}
    for check_id, entry in overrides_raw.items():
        if not isinstance(entry, Mapping):
            raise ConfigError(
                f"scoring config {source}: check_overrides.{check_id} must be a table"
            )
        fixed = entry.get("fixed_severity")
        maximum = entry.get("max_severity")
        overrides[str(check_id)] = CheckOverride(
            fixed_severity=_severity(fixed, f"check_overrides.{check_id}.fixed_severity", source)
            if fixed is not None
            else None,
            max_severity=_severity(maximum, f"check_overrides.{check_id}.max_severity", source)
            if maximum is not None
            else None,
        )

    return ScoringConfig(
        weights=weights,
        evidence_multipliers=evidence,
        confidence_multipliers=confidence,
        precondition_penalty=penalty,
        precondition_floor=floor,
        thresholds=thresholds,
        severity_caps=caps,
        check_overrides=overrides,
        source=source,
    )


def _float_map(raw: Any, name: str, source: str) -> dict[str, float]:
    if not isinstance(raw, Mapping):
        raise ConfigError(f"scoring config {source}: {name} must be a table")
    return {str(k): _float(v, f"{name}.{k}", source) for k, v in raw.items()}


def _float(value: Any, name: str, source: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"scoring config {source}: {name} must be a number")
    return float(value)


def _severity(value: Any, name: str, source: str) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError as exc:
        raise ConfigError(
            f"scoring config {source}: {name} has invalid severity {value!r}"
        ) from exc


def _evidence_kind(value: Any, source: str) -> EvidenceKind:
    try:
        return EvidenceKind(str(value).lower())
    except ValueError as exc:
        raise ConfigError(f"scoring config {source}: unknown evidence kind {value!r}") from exc


class Scorer:
    """Turn factor values into a score, a severity and an auditable breakdown."""

    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or load_scoring_config()

    def score(
        self,
        factors: Mapping[str, FactorScore],
        evidence_kind: EvidenceKind,
        confidence: Confidence,
        preconditions: Sequence[str] = (),
        check_id: str | None = None,
    ) -> tuple[Severity, float, ScoreBreakdown]:
        cfg = self.config
        total_weight = sum(cfg.weights.values())
        resolved: dict[str, FactorScore] = {}
        weighted = 0.0
        for name in FACTORS:
            factor = factors.get(name) or FactorScore(0.0, cfg.weights[name], "not applicable")
            value = min(1.0, max(0.0, factor.value))
            resolved[name] = FactorScore(value, cfg.weights[name], factor.rationale)
            weighted += cfg.weights[name] * value
        base = 100.0 * weighted / total_weight
        conf_mult = cfg.evidence_multipliers[evidence_kind] * cfg.confidence_multipliers[confidence]
        pre_mult = max(cfg.precondition_floor, 1.0 - cfg.precondition_penalty * len(preconditions))
        raw = base * conf_mult * pre_mult

        severity = self.severity_for(raw)
        cap_applied: str | None = None
        cap = cfg.severity_caps.get(evidence_kind)
        if cap is not None and severity.rank > cap.rank:
            severity = cap
            cap_applied = f"capped at {cap.value} because evidence is {evidence_kind.value}"
        override = cfg.check_overrides.get(check_id or "")
        if override is not None:
            if override.max_severity is not None and severity.rank > override.max_severity.rank:
                severity = override.max_severity
                cap_applied = f"capped at {severity.value} by check override"
            if override.fixed_severity is not None:
                severity = override.fixed_severity
                cap_applied = f"fixed at {severity.value} by check override"

        breakdown = ScoreBreakdown(
            factors=resolved,
            base_score=round(base, 2),
            confidence_multiplier=round(conf_mult, 4),
            precondition_multiplier=round(pre_mult, 4),
            raw_score=round(raw, 2),
            final_score=round(raw, 2),
            cap_applied=cap_applied,
        )
        return severity, round(raw, 2), breakdown

    def severity_for(self, score: float) -> Severity:
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            if score >= self.config.thresholds[sev]:
                return sev
        return Severity.INFORMATIONAL
