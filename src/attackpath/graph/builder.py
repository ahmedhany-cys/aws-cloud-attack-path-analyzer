"""Build the permission-relationship graph from an environment snapshot.

Structural edges (group membership, policy attachment, trust statements, Lambda
execution roles) are observed facts. Capability edges are produced by asking the
policy evaluator concrete questions:

* ``can-assume``: the trust policy and, where AWS requires it, the caller's own
  identity policy allow ``sts:AssumeRole``;
* ``can-access``: identity policy, permissions boundary and bucket policy allow one
  of the probed S3 action classes (read, list, write, delete, policy).

Every capability edge carries the statements that justify it, a confidence level
and the preconditions the evaluator could not discharge.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from attackpath.config import AnalysisConfig
from attackpath.graph.model import AttackGraph, Edge, EdgeType, Node, NodeType
from attackpath.iam.evaluator import Decision, EvaluationResult, PolicyEvaluator
from attackpath.iam.matching import action_breadth, resource_breadth, service_of
from attackpath.iam.principals import PrincipalIdentity
from attackpath.models.arn import account_of, is_account_root, parse_arn
from attackpath.models.environment import (
    Environment,
    Principal,
    PrincipalKind,
    Role,
    S3Bucket,
    Sensitivity,
    User,
)
from attackpath.models.finding import Confidence, Evidence, EvidenceKind
from attackpath.models.policy import Condition, Effect, PolicyDocument, Statement
from attackpath.tri import Tri

ANONYMOUS_NODE_ID = "anonymous"

#: (class name, action, resource template) probed for every principal/bucket pair.
ACCESS_CLASSES: tuple[tuple[str, str, str], ...] = (
    ("read", "s3:GetObject", "{arn}/*"),
    ("list", "s3:ListBucket", "{arn}"),
    ("write", "s3:PutObject", "{arn}/*"),
    ("delete", "s3:DeleteObject", "{arn}/*"),
    ("policy", "s3:PutBucketPolicy", "{arn}"),
)
WRITE_CLASSES: frozenset[str] = frozenset({"write", "delete", "policy"})


def account_node_id(account_id: str) -> str:
    return f"account:{account_id}"


def service_node_id(service: str) -> str:
    return f"service:{service.lower()}"


@dataclass(frozen=True)
class TrustEntry:
    """One principal named by an ``Allow`` statement of a role's trust policy."""

    role_arn: str
    statement: Statement
    kind: str  # anonymous | same-account | same-account-principal | cross-account |
    # cross-account-principal | service | federated
    value: str
    node_id: str
    conditions: tuple[Condition, ...]

    @property
    def crosses_account_boundary(self) -> bool:
        return self.kind in ("anonymous", "cross-account", "cross-account-principal")

    @property
    def condition_keys(self) -> tuple[str, ...]:
        return tuple(c.key for c in self.conditions)

    @property
    def requires_external_id(self) -> bool:
        return any(c.key.lower() == "sts:externalid" for c in self.conditions)


def trust_entries(role: Role) -> list[TrustEntry]:
    """Classify every principal an ``Allow`` statement of the trust policy names."""
    entries: list[TrustEntry] = []
    for statement in role.trust_policy.statements:
        if statement.effect is not Effect.ALLOW or statement.principal is None:
            continue
        spec = statement.principal
        conditions = statement.conditions
        if spec.wildcard or "*" in spec.aws:
            entries.append(
                TrustEntry(role.arn, statement, "anonymous", "*", ANONYMOUS_NODE_ID, conditions)
            )
        for entry in spec.aws:
            if entry == "*":
                continue
            account = account_of(entry)
            if is_account_root(entry):
                if account == role.account_id:
                    kind, node_id = "same-account", account_node_id(role.account_id)
                else:
                    kind, node_id = "cross-account", account_node_id(account or entry)
            elif account == role.account_id:
                kind, node_id = "same-account-principal", entry
            else:
                kind, node_id = "cross-account-principal", entry
            entries.append(TrustEntry(role.arn, statement, kind, entry, node_id, conditions))
        for service in spec.service:
            entries.append(
                TrustEntry(
                    role.arn, statement, "service", service, service_node_id(service), conditions
                )
            )
        for federated in spec.federated:
            entries.append(
                TrustEntry(
                    role.arn,
                    statement,
                    "federated",
                    federated,
                    f"federated:{federated}",
                    conditions,
                )
            )
    return entries


def build_graph(
    env: Environment, evaluator: PolicyEvaluator, config: AnalysisConfig | None = None
) -> AttackGraph:
    config = config or AnalysisConfig()
    graph = AttackGraph(config.limits)
    _add_nodes(graph, env)
    _add_structural_edges(graph, env)
    _flag_privilege(graph, env, evaluator)
    _add_assume_edges(graph, env, evaluator)
    _add_access_edges(graph, env, evaluator)
    _add_lambda_invoke_edges(graph, env, evaluator)
    return graph


# ---------------------------------------------------------------------------
# nodes and structure
# ---------------------------------------------------------------------------


def _add_nodes(graph: AttackGraph, env: Environment) -> None:
    graph.add_node(
        Node(
            id=account_node_id(env.account_id),
            type=NodeType.ACCOUNT,
            label=f"account {env.account_id}",
            account_id=env.account_id,
        )
    )
    for user in env.users:
        graph.add_node(
            Node(
                id=user.arn,
                type=NodeType.USER,
                label=user.name,
                account_id=user.account_id,
                attrs={
                    "active_access_keys": len(user.active_access_keys),
                    "mfa_enabled": user.mfa_enabled,
                    "console_access": user.console_access,
                },
            )
        )
    for group in env.groups:
        graph.add_node(
            Node(id=group.arn, type=NodeType.GROUP, label=group.name, account_id=group.account_id)
        )
    for role in env.roles:
        graph.add_node(
            Node(id=role.arn, type=NodeType.ROLE, label=role.name, account_id=role.account_id)
        )
    for policy in env.managed_policies:
        graph.add_node(
            Node(
                id=policy.arn,
                type=NodeType.MANAGED_POLICY,
                label=policy.name,
                account_id=None if policy.is_aws_managed else account_of(policy.arn),
                attrs={"aws_managed": policy.is_aws_managed},
            )
        )
    for bucket in env.s3_buckets:
        graph.add_node(
            Node(
                id=bucket.arn,
                type=NodeType.S3_BUCKET,
                label=bucket.name,
                account_id=bucket.account_id,
                sensitivity=bucket.sensitivity,
                attrs={"sensitive": bucket.sensitivity in (Sensitivity.HIGH, Sensitivity.MEDIUM)},
            )
        )
    for fn in env.lambda_functions:
        graph.add_node(
            Node(id=fn.arn, type=NodeType.LAMBDA_FUNCTION, label=fn.name, account_id=fn.account_id)
        )
    for external in env.external_principals:
        _external_node(graph, external.arn, known=external.known, description=external.description)


def _external_node(
    graph: AttackGraph, arn: str, *, known: bool = False, description: str | None = None
) -> Node:
    if arn == "*":
        return graph.add_node(
            Node(
                id=ANONYMOUS_NODE_ID, type=NodeType.ANONYMOUS, label="any AWS principal / anonymous"
            )
        )
    account = account_of(arn)
    if is_account_root(arn):
        return graph.add_node(
            Node(
                id=account_node_id(account or arn),
                type=NodeType.EXTERNAL_ACCOUNT,
                label=f"account {account or arn}",
                account_id=account,
                attrs={"known": known, "description": description},
            )
        )
    parsed = parse_arn(arn)
    label = parsed.resource if parsed else arn
    return graph.add_node(
        Node(
            id=arn,
            type=NodeType.EXTERNAL_PRINCIPAL,
            label=f"{label} ({account})" if account else label,
            account_id=account,
            attrs={"known": known, "description": description},
        )
    )


def _placeholder_principal(graph: AttackGraph, arn: str) -> Node:
    """A same-account principal referenced by configuration but absent from the snapshot."""
    parsed = parse_arn(arn)
    node_type = NodeType.ROLE if parsed and parsed.resource_type == "role" else NodeType.USER
    return graph.add_node(
        Node(
            id=arn,
            type=node_type,
            label=(parsed.resource_name if parsed else arn) + " (not in snapshot)",
            account_id=account_of(arn),
            attrs={"unresolved": True},
        )
    )


def _add_structural_edges(graph: AttackGraph, env: Environment) -> None:
    for user in env.users:
        for group_name in user.groups:
            group = env.group_by_name(group_name)
            if group is not None:
                graph.add_edge(Edge(user.arn, group.arn, EdgeType.MEMBER_OF, "member of"))
    for principal in env.principals():
        for policy_arn in principal.attached_policy_arns:
            if env.managed_policy(policy_arn) is not None:
                graph.add_edge(
                    Edge(principal.arn, policy_arn, EdgeType.HAS_POLICY, "attached policy")
                )
    for group in env.groups:
        for policy_arn in group.attached_policy_arns:
            if env.managed_policy(policy_arn) is not None:
                graph.add_edge(Edge(group.arn, policy_arn, EdgeType.HAS_POLICY, "attached policy"))
    for fn in env.lambda_functions:
        if not fn.role_arn:
            continue
        if env.role(fn.role_arn) is None:
            _placeholder_principal(graph, fn.role_arn)
        graph.add_edge(
            Edge(
                fn.arn,
                fn.role_arn,
                EdgeType.EXECUTES_AS,
                "executes as",
                evidence=(
                    Evidence(source=f"lambda:{fn.arn}", detail=f"execution role {fn.role_arn}"),
                ),
            )
        )
    for role in env.roles:
        for entry in trust_entries(role):
            target = _trust_target_node(graph, env, entry)
            conditions = "; ".join(c.describe() for c in entry.conditions)
            graph.add_edge(
                Edge(
                    role.arn,
                    target.id,
                    EdgeType.TRUSTS,
                    f"trusts ({entry.kind})" + (" with conditions" if conditions else ""),
                    evidence=(
                        Evidence(
                            source=role.trust_policy.source,
                            detail=f"{entry.statement.label()} names {entry.value}"
                            + (f" with conditions: {conditions}" if conditions else ""),
                            statement=entry.statement.raw,
                        ),
                    ),
                    attrs={
                        "kind": entry.kind,
                        "conditions": [c.describe() for c in entry.conditions],
                    },
                )
            )


def _trust_target_node(graph: AttackGraph, env: Environment, entry: TrustEntry) -> Node:
    if entry.kind == "anonymous":
        return _external_node(graph, "*")
    if entry.kind == "same-account":
        return graph.add_node(
            Node(
                id=entry.node_id,
                type=NodeType.ACCOUNT,
                label=f"account {env.account_id}",
                account_id=env.account_id,
            )
        )
    if entry.kind == "same-account-principal":
        existing = graph.node(entry.value)
        return existing if existing is not None else _placeholder_principal(graph, entry.value)
    if entry.kind in ("cross-account", "cross-account-principal"):
        return _external_node(graph, entry.value)
    if entry.kind == "service":
        return graph.add_node(
            Node(id=entry.node_id, type=NodeType.SERVICE, label=entry.value.lower())
        )
    return graph.add_node(
        Node(
            id=entry.node_id,
            type=NodeType.EXTERNAL_PRINCIPAL,
            label=f"federated {entry.value}",
            attrs={"federated": True},
        )
    )


# ---------------------------------------------------------------------------
# privilege estimate
# ---------------------------------------------------------------------------


def allow_statements(docs: Iterable[PolicyDocument]) -> list[tuple[PolicyDocument, Statement]]:
    return [(doc, st) for doc in docs for st in doc.statements if st.effect is Effect.ALLOW]


def permission_breadth(docs: Iterable[PolicyDocument]) -> float:
    """Estimate 0..1 of how broad the identity's allowed permissions are."""
    best = 0.0
    for _, st in allow_statements(docs):
        actions = 0.9 if st.uses_not_action else action_breadth(st.actions)
        resources = 0.9 if st.uses_not_resource else resource_breadth(st.resources)
        best = max(best, actions * resources)
    return best


def _flag_privilege(graph: AttackGraph, env: Environment, evaluator: PolicyEvaluator) -> None:
    for principal in env.principals():
        node = graph.node(principal.arn)
        if node is None:
            continue
        is_admin, refs = evaluator.is_admin_equivalent(principal)
        node.is_admin = is_admin
        node.attrs["admin_evidence"] = [ref.describe() for ref in refs]
        breadth = permission_breadth(evaluator.identity_policies(principal))
        node.attrs["breadth"] = round(breadth, 3)
        if is_admin is Tri.TRUE:
            node.attrs["privilege"] = 1.0
        elif is_admin is Tri.UNKNOWN:
            node.attrs["privilege"] = max(0.8, breadth)
        else:
            node.attrs["privilege"] = breadth
        node.attrs["unresolved_policies"] = evaluator.unresolved_policies_for(principal)
        if isinstance(principal, Role):
            entries = trust_entries(principal)
            node.attrs["workload_services"] = sorted(
                {e.value.lower() for e in entries if e.kind == "service"}
            )
            node.attrs["externally_trusted"] = any(e.crosses_account_boundary for e in entries)
    for role_arn, functions in env.roles_used_by_lambdas().items():
        node = graph.node(role_arn)
        if node is not None:
            node.attrs["used_by_lambdas"] = sorted(fn.name for fn in functions)


# ---------------------------------------------------------------------------
# can-assume edges
# ---------------------------------------------------------------------------


def _add_assume_edges(graph: AttackGraph, env: Environment, evaluator: PolicyEvaluator) -> None:
    for role in env.roles:
        entries = trust_entries(role)
        if not entries:
            continue
        broad = any(e.kind in ("anonymous", "same-account") for e in entries)
        local_candidates: list[Principal]
        if broad:
            local_candidates = [p for p in env.principals() if p.arn != role.arn]
        else:
            named = {e.value for e in entries if e.kind == "same-account-principal"}
            local_candidates = [p for p in env.principals() if p.arn in named and p.arn != role.arn]
        for principal in local_candidates:
            result = evaluator.can_assume(PrincipalIdentity.from_principal(principal), role)
            if not result.is_possible:
                continue
            if (
                result.decision is Decision.INDETERMINATE
                and result.identity_permission is not None
                and not result.identity_permission.allow_matches
            ):
                # The only uncertainty is a policy document missing from the snapshot;
                # that is reported once by the coverage check, not as a conditional edge.
                continue
            if result.decision is Decision.ALLOWED:
                confidence, kind = Confidence.HIGH, EvidenceKind.OBSERVED
            else:
                confidence, kind = Confidence.LOW, EvidenceKind.INDETERMINATE
            graph.add_edge(
                Edge(
                    principal.arn,
                    role.arn,
                    EdgeType.CAN_ASSUME,
                    "sts:AssumeRole"
                    + (" (conditional)" if kind is EvidenceKind.INDETERMINATE else ""),
                    confidence=confidence,
                    evidence_kind=kind,
                    evidence=tuple(_dedupe_evidence(result.evidence())),
                    preconditions=tuple(result.preconditions),
                    attrs={"decision": result.decision.value, "notes": list(result.notes)},
                )
            )
        seen_external: set[str] = set()
        for entry in entries:
            if not entry.crosses_account_boundary or entry.node_id in seen_external:
                continue
            seen_external.add(entry.node_id)
            identity = PrincipalIdentity.external(entry.value)
            result = evaluator.can_assume(identity, role)
            if not result.is_possible:
                continue
            source = _external_node(graph, entry.value)
            if entry.kind == "anonymous":
                confidence = (
                    Confidence.HIGH if result.decision is Decision.ALLOWED else Confidence.LOW
                )
                kind = (
                    EvidenceKind.OBSERVED
                    if result.decision is Decision.ALLOWED
                    else EvidenceKind.INDETERMINATE
                )
            else:
                confidence, kind = Confidence.MEDIUM, EvidenceKind.HYPOTHETICAL
            graph.add_edge(
                Edge(
                    source.id,
                    role.arn,
                    EdgeType.CAN_ASSUME,
                    "sts:AssumeRole" + (" (conditional)" if result.preconditions else ""),
                    confidence=confidence,
                    evidence_kind=kind,
                    evidence=tuple(_dedupe_evidence(result.evidence())),
                    preconditions=tuple(result.preconditions),
                    attrs={"decision": result.decision.value, "notes": list(result.notes)},
                )
            )


# ---------------------------------------------------------------------------
# can-access edges
# ---------------------------------------------------------------------------


def _may_touch_service(docs: Iterable[PolicyDocument], service: str) -> bool:
    """Cheap pre-filter: could any Allow statement match an action of ``service``?"""
    for _, st in allow_statements(docs):
        if st.uses_not_action:
            return True
        for pattern in st.actions:
            if ":" not in pattern:
                return True
            prefix = service_of(pattern)
            if prefix == service or "*" in prefix or "?" in prefix:
                return True
    return False


def _add_access_edges(graph: AttackGraph, env: Environment, evaluator: PolicyEvaluator) -> None:
    for bucket in env.s3_buckets:
        for principal in env.principals():
            docs = evaluator.identity_policies(principal)
            if (
                bucket.bucket_policy is None
                and not _may_touch_service(docs, "s3")
                and not evaluator.unresolved_policies_for(principal)
            ):
                continue
            results = {
                cls: evaluator.evaluate(
                    principal,
                    action,
                    template.format(arn=bucket.arn),
                    resource_policy=bucket.bucket_policy,
                    resource_account=bucket.account_id,
                )
                for cls, action, template in ACCESS_CLASSES
            }
            _add_access_edge(graph, principal.arn, bucket, results, external=False)
        if bucket.bucket_policy is not None:
            _add_external_access_edges(graph, bucket, bucket.bucket_policy, evaluator)


def _add_external_access_edges(
    graph: AttackGraph, bucket: S3Bucket, policy: PolicyDocument, evaluator: PolicyEvaluator
) -> None:
    for identity, node_arn in _external_identities(policy, bucket.account_id):
        results = {
            cls: evaluator.evaluate_resource_policy(
                policy, identity, action, template.format(arn=bucket.arn)
            )
            for cls, action, template in ACCESS_CLASSES
        }
        if any(r.is_possible for r in results.values()):
            node = _external_node(graph, node_arn)
            pab = bucket.public_access_block
            blocked = node_arn == "*" and pab is not None and pab.restrict_public_buckets
            _add_access_edge(
                graph,
                node.id,
                bucket,
                results,
                external=node_arn != "*",
                blocked_by_public_access_block=blocked,
            )


def _external_identities(
    policy: PolicyDocument, home_account: str
) -> list[tuple[PrincipalIdentity, str]]:
    """Identities outside the account that a resource policy's Allow statements name."""
    found: dict[str, PrincipalIdentity] = {}
    for st in policy.statements:
        if st.effect is not Effect.ALLOW or st.principal is None:
            continue
        if st.principal.wildcard or "*" in st.principal.aws:
            found.setdefault("*", PrincipalIdentity.anonymous())
        for entry in st.principal.aws:
            if entry == "*" or account_of(entry) == home_account:
                continue
            found.setdefault(entry, PrincipalIdentity.external(entry))
    return [(identity, arn) for arn, identity in found.items()]


def _add_access_edge(
    graph: AttackGraph,
    source_id: str,
    bucket: S3Bucket,
    results: dict[str, EvaluationResult],
    *,
    external: bool,
    blocked_by_public_access_block: bool = False,
) -> None:
    possible = {cls: r for cls, r in results.items() if r.is_possible}
    if not possible or not any(r.allow_matches for r in possible.values()):
        # Nothing concrete grants access: the uncertainty comes only from documents
        # missing from the snapshot, which the coverage check reports once.
        return
    access = {cls: r.decision.value for cls, r in possible.items()}
    # Access that exists only because the bucket policy grants it to everyone is
    # reported once as a public-exposure finding, not once per principal.
    public_only = not external and all(
        all(m.layer == "resource" and _names_everyone(m.ref.statement) for m in r.allow_matches)
        for r in possible.values()
    )
    denied = {
        cls: r.decision.value for cls, r in results.items() if r.decision is Decision.EXPLICIT_DENY
    }
    any_allowed = any(r.decision is Decision.ALLOWED for r in possible.values())
    labels = [cls + ("" if r.decision is Decision.ALLOWED else "?") for cls, r in possible.items()]
    preconditions: list[str] = []
    evidence: list[Evidence] = []
    for r in possible.values():
        for reason in r.unknown_reasons():
            if reason not in preconditions:
                preconditions.append(reason)
        evidence.extend(m.to_evidence() for m in r.allow_matches)
    if external:
        preconditions.append(
            f"a principal in account {account_of(source_id) or 'unknown'} must also hold an "
            "identity-policy Allow for the S3 action (that account is outside the snapshot)"
        )
        confidence, kind = Confidence.MEDIUM, EvidenceKind.HYPOTHETICAL
    elif any_allowed:
        confidence, kind = Confidence.HIGH, EvidenceKind.OBSERVED
    else:
        confidence, kind = Confidence.LOW, EvidenceKind.INDETERMINATE
    graph.add_edge(
        Edge(
            source_id,
            bucket.arn,
            EdgeType.CAN_ACCESS,
            "s3 " + ", ".join(labels),
            confidence=confidence,
            evidence_kind=kind,
            evidence=tuple(_dedupe_evidence(evidence)),
            preconditions=tuple(preconditions),
            traversable=not public_only and not blocked_by_public_access_block,
            attrs={
                "access": access,
                "denied": denied,
                "write": bool(WRITE_CLASSES & set(access)),
                "public_only": public_only,
                "blocked_by_public_access_block": blocked_by_public_access_block,
            },
        )
    )


def _names_everyone(statement: dict[str, Any]) -> bool:
    """True when a raw statement's Principal element grants to every AWS principal."""
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False


# ---------------------------------------------------------------------------
# lambda invocation edges (exposure only; functions are not path targets)
# ---------------------------------------------------------------------------


def _add_lambda_invoke_edges(
    graph: AttackGraph, env: Environment, evaluator: PolicyEvaluator
) -> None:
    for fn in env.lambda_functions:
        if fn.resource_policy is None:
            continue
        for identity, node_arn in _external_identities(fn.resource_policy, fn.account_id):
            results = {
                action: evaluator.evaluate_resource_policy(
                    fn.resource_policy, identity, action, fn.arn
                )
                for action in ("lambda:InvokeFunction", "lambda:InvokeFunctionUrl")
            }
            possible = {a: r for a, r in results.items() if r.is_possible}
            if not possible:
                continue
            node = _external_node(graph, node_arn)
            any_allowed = any(r.decision is Decision.ALLOWED for r in possible.values())
            evidence = [m.to_evidence() for r in possible.values() for m in r.allow_matches]
            graph.add_edge(
                Edge(
                    node.id,
                    fn.arn,
                    EdgeType.CAN_ACCESS,
                    "invoke" + ("" if any_allowed else "?"),
                    confidence=Confidence.HIGH if any_allowed else Confidence.LOW,
                    evidence_kind=EvidenceKind.OBSERVED
                    if any_allowed
                    else EvidenceKind.INDETERMINATE,
                    evidence=tuple(_dedupe_evidence(evidence)),
                    preconditions=tuple(
                        reason for r in possible.values() for reason in r.unknown_reasons()
                    ),
                    attrs={"access": {a: r.decision.value for a, r in possible.items()}},
                )
            )


def _dedupe_evidence(items: Sequence[Evidence], limit: int = 8) -> list[Evidence]:
    out: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (item.source, item.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def principal_label(principal: Principal | User | Role) -> str:
    kind = "user" if principal.kind is PrincipalKind.USER else "role"
    return f"{kind} {principal.name}"
