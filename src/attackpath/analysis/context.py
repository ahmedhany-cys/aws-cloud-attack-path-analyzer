"""Shared state and helpers for the analysis checks."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from attackpath.config import AnalysisConfig
from attackpath.graph.builder import TrustEntry, allow_statements, trust_entries
from attackpath.graph.model import AttackGraph, Node, NodeType
from attackpath.graph.paths import PathSearchResult
from attackpath.iam.evaluator import PolicyEvaluator
from attackpath.models.environment import (
    Environment,
    Principal,
    PrincipalKind,
    Role,
    S3Bucket,
    Sensitivity,
    User,
)
from attackpath.models.finding import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    FactorScore,
    Finding,
    PathStep,
    Remediation,
)
from attackpath.models.policy import PolicyDocument, Statement
from attackpath.scoring.model import Scorer

_SENSITIVITY_VALUE: dict[Sensitivity, float] = {
    Sensitivity.HIGH: 1.0,
    Sensitivity.MEDIUM: 0.6,
    Sensitivity.LOW: 0.2,
    Sensitivity.UNKNOWN: 0.4,
}


def finding_id(check_id: str, *parts: str | None) -> str:
    """Deterministic identifier so re-runs and regression tests can compare findings."""
    key = "|".join([check_id, *[p or "" for p in parts]])
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
    return f"APA-{check_id}-{digest}"


@dataclass
class AnalysisContext:
    env: Environment
    evaluator: PolicyEvaluator
    graph: AttackGraph
    paths: PathSearchResult
    config: AnalysisConfig
    scorer: Scorer
    mode: str = "environment"

    # ---- finding construction -------------------------------------------
    def finding(
        self,
        *,
        check_id: str,
        category: Category,
        title: str,
        description: str,
        impact: str,
        remediation: Remediation,
        evidence_kind: EvidenceKind,
        confidence: Confidence,
        factors: dict[str, FactorScore],
        principal: str | None = None,
        resource: str | None = None,
        evidence: Iterable[Evidence] = (),
        attack_path: Iterable[PathStep] = (),
        preconditions: Iterable[str] = (),
        references: Iterable[str] = (),
        tags: Iterable[str] = (),
        key: Sequence[str] = (),
    ) -> Finding:
        preconditions_list = list(dict.fromkeys(preconditions))
        severity, score, breakdown = self.scorer.score(
            factors, evidence_kind, confidence, preconditions_list, check_id
        )
        return Finding(
            id=finding_id(check_id, principal, resource, *key),
            check_id=check_id,
            category=category,
            title=title[:1].upper() + title[1:],
            severity=severity,
            confidence=confidence,
            evidence_kind=evidence_kind,
            description=description,
            impact=impact,
            remediation=remediation,
            affected_principal=principal,
            affected_resource=resource,
            evidence=list(evidence),
            attack_path=list(attack_path),
            preconditions=preconditions_list,
            references=list(dict.fromkeys(references)),
            score=score,
            score_breakdown=breakdown,
            tags=list(dict.fromkeys(tags)),
        )

    # ---- labels -----------------------------------------------------------
    @staticmethod
    def label(principal: Principal) -> str:
        kind = "user" if principal.kind is PrincipalKind.USER else "role"
        return f"{kind} {principal.name}"

    def node_label(self, node_id: str) -> str:
        node = self.graph.node(node_id)
        if node is None:
            return node_id
        prefixes = {
            NodeType.USER: "user",
            NodeType.ROLE: "role",
            NodeType.S3_BUCKET: "bucket",
            NodeType.LAMBDA_FUNCTION: "function",
            NodeType.EC2_INSTANCE: "instance",
        }
        prefix = prefixes.get(node.type)
        return f"{prefix} {node.label}" if prefix else node.label

    # ---- factor helpers ---------------------------------------------------
    def exposure(self, principal: Principal) -> FactorScore:
        node = self.graph.node(principal.arn)
        return self.exposure_for_node(node) if node else FactorScore(0.4, 0, "unknown identity")

    def exposure_for_node(self, node: Node) -> FactorScore:
        if node.type is NodeType.ANONYMOUS:
            return FactorScore(1.0, 0, "reachable by any AWS principal or anonymously")
        if node.type is NodeType.INTERNET:
            return FactorScore(1.0, 0, "reachable from any internet address")
        if node.type is NodeType.EC2_INSTANCE:
            if node.attrs.get("public_ingress") and node.attrs.get("public_ip"):
                return FactorScore(
                    0.9, 0, "instance with a public address and ingress open to the internet"
                )
            return FactorScore(0.5, 0, "workload identity (instance can be compromised)")
        if node.type in (NodeType.EXTERNAL_ACCOUNT, NodeType.EXTERNAL_PRINCIPAL):
            if node.attrs.get("known"):
                return FactorScore(
                    0.6, 0, "identity in a known partner account outside the snapshot"
                )
            return FactorScore(0.8, 0, "identity in another account outside the snapshot")
        if node.type is NodeType.LAMBDA_FUNCTION:
            return FactorScore(0.5, 0, "workload identity (function code can be compromised)")
        if node.type is NodeType.USER:
            value, reasons = 0.4, ["human identity"]
            if node.attrs.get("active_access_keys"):
                value += 0.3
                reasons.append("has active long-lived access keys")
            if node.attrs.get("console_access") and node.attrs.get("mfa_enabled") is False:
                value += 0.2
                reasons.append("console access without MFA")
            elif node.attrs.get("mfa_enabled") is None:
                value += 0.1
                reasons.append("MFA state unknown")
            return FactorScore(min(1.0, value), 0, "; ".join(reasons))
        if node.type is NodeType.ROLE:
            value, reasons = 0.3, ["role"]
            if node.attrs.get("externally_trusted"):
                value += 0.4
                reasons.append("trusted by principals outside the account")
            if (
                node.attrs.get("workload_services")
                or node.attrs.get("used_by_lambdas")
                or node.attrs.get("used_by_instances")
            ):
                value += 0.2
                reasons.append("workload execution role")
            return FactorScore(min(1.0, value), 0, "; ".join(reasons))
        return FactorScore(0.4, 0, "other identity")

    @staticmethod
    def sensitivity_factor(bucket: S3Bucket) -> FactorScore:
        return FactorScore(
            _SENSITIVITY_VALUE[bucket.sensitivity],
            0,
            f"bucket sensitivity declared as {bucket.sensitivity.value}",
        )

    def privilege_factor(self, node: Node) -> FactorScore:
        if node.is_admin.is_true:
            return FactorScore(1.0, 0, "administrative permissions")
        if node.is_admin.is_unknown:
            return FactorScore(0.8, 0, "possibly administrative (depends on unresolved policies)")
        sensitive = self.sensitive_buckets_reachable(node.id)
        if sensitive:
            return FactorScore(
                max(0.7, node.privilege), 0, f"can access sensitive buckets: {', '.join(sensitive)}"
            )
        return FactorScore(node.privilege, 0, f"estimated permission breadth {node.privilege:.2f}")

    def sensitive_buckets_reachable(self, node_id: str) -> list[str]:
        """Sensitive buckets the identity itself can reach (access that exists only because a
        bucket is public, or that Block Public Access neutralizes, is not the identity's privilege)."""
        names: list[str] = []
        for edge in self.graph.out_edges(node_id):
            if not edge.traversable:
                continue
            target = self.graph.node(edge.target)
            if target and target.type is NodeType.S3_BUCKET and target.attrs.get("sensitive"):
                names.append(target.label)
        return sorted(names)

    @staticmethod
    def hops_factor(length: int) -> FactorScore:
        value = max(0.2, 1.0 - 0.2 * (length - 1))
        return FactorScore(value, 0, f"{length} hop(s)")

    # ---- environment helpers ---------------------------------------------
    def identity_allow_statements(
        self, principal: Principal
    ) -> list[tuple[PolicyDocument, Statement]]:
        return allow_statements(self.evaluator.identity_policies(principal))

    def trust(self, role: Role) -> list[TrustEntry]:
        return trust_entries(role)

    def is_workload(self, role: Role) -> bool:
        node = self.graph.node(role.arn)
        return bool(
            node
            and (
                node.attrs.get("workload_services")
                or node.attrs.get("used_by_lambdas")
                or node.attrs.get("used_by_instances")
            )
        )

    def max_bucket_sensitivity(self, node_id: str) -> FactorScore:
        """The most sensitive bucket reachable from ``node_id`` in one ``can-access`` hop."""
        best: FactorScore | None = None
        for edge in self.graph.out_edges(node_id):
            bucket = self.env.bucket(edge.target) if edge.traversable else None
            if bucket is None:
                continue
            candidate = self.sensitivity_factor(bucket)
            if best is None or candidate.value > best.value:
                best = candidate
        return best or FactorScore(0.4, 0, "no bucket access known for the identity")

    def is_admin(self, principal: Principal) -> bool:
        node = self.graph.node(principal.arn)
        return bool(node and node.is_admin.is_true)

    def principal_by_arn(self, arn: str) -> Principal | None:
        return self.env.principal(arn)

    @staticmethod
    def evidence_from(
        docs: Iterable[tuple[PolicyDocument, Statement]], note: str = ""
    ) -> list[Evidence]:
        return [
            Evidence(
                source=doc.source,
                detail=f"{st.label()}{(' ' + note) if note else ''}",
                statement=st.raw,
            )
            for doc, st in docs
        ]

    @staticmethod
    def user_or_role(principal: Principal) -> str:
        return "user" if isinstance(principal, User) else "role"

    def summary_attrs(self) -> dict[str, Any]:
        return {"mode": self.mode, "paths": len(self.paths.paths)}
