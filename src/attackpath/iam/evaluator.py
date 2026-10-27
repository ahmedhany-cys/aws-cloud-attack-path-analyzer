"""Tri-state IAM policy evaluator.

Implemented semantics (see ``docs/methodology.md`` for the full list):

* Identity-based policies: inline + attached managed policies of users and roles,
  plus group policies for users.
* Explicit ``Deny`` always wins over ``Allow``; the absence of an ``Allow`` is an
  implicit deny.
* Permissions boundaries intersect identity permissions (same-account resource
  policies that name the principal directly are not limited by a boundary).
* Resource-based policies (S3 bucket policies, Lambda resource policies, role trust
  policies): same-account callers need an allow from *either* side, cross-account
  callers need an allow from *both* sides.
* Conditions are evaluated against the request context that can be derived from the
  snapshot; anything else is ``UNKNOWN`` and surfaces as an indeterminate decision.

Not implemented: service control policies, session policies, VPC endpoint policies,
S3 access point policies, and service-specific authorization rules. The evaluator
never converts an unknown into a decision.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum

from attackpath.iam.conditions import RequestContext, evaluate_conditions
from attackpath.iam.matching import (
    POLICY_VARIABLE_VERSION,
    statement_action_matches,
    statement_resource_matches,
)
from attackpath.iam.principals import (
    IdentityKind,
    PrincipalIdentity,
    principal_entry_names_account,
    statement_principal_matches,
)
from attackpath.models.arn import account_of, normalize_principal_arn
from attackpath.models.environment import Environment, Principal, PrincipalKind, Role, User
from attackpath.models.finding import Evidence
from attackpath.models.policy import Effect, PolicyDocument, PolicyRef
from attackpath.tri import Tri, tri_and, tri_or

ADMIN_PROBE_ACTIONS: tuple[str, ...] = (
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
    "s3:GetObject",
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "kms:Decrypt",
)


class Decision(str, Enum):
    ALLOWED = "allowed"
    EXPLICIT_DENY = "explicit-deny"
    IMPLICIT_DENY = "implicit-deny"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class StatementMatch:
    ref: PolicyRef
    effect: Effect
    result: Tri
    layer: str
    reasons: tuple[str, ...] = ()

    def to_evidence(self) -> Evidence:
        qualifier = (
            "applies" if self.result is Tri.TRUE else "applies only if: " + "; ".join(self.reasons)
        )
        return Evidence(
            source=self.ref.source,
            detail=f"{self.ref.describe()} {qualifier}",
            statement=self.ref.statement,
        )


@dataclass
class EvaluationResult:
    principal_arn: str
    action: str
    resource: str
    decision: Decision
    matches: list[StatementMatch] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    unresolved_policies: list[str] = field(default_factory=list)
    identity_allow: Tri = Tri.FALSE
    identity_deny: Tri = Tri.FALSE
    boundary_allow: Tri | None = None
    resource_allow: Tri | None = None
    resource_deny: Tri | None = None

    @property
    def allow_matches(self) -> list[StatementMatch]:
        return [m for m in self.matches if m.effect is Effect.ALLOW]

    @property
    def deny_matches(self) -> list[StatementMatch]:
        return [m for m in self.matches if m.effect is Effect.DENY]

    @property
    def is_allowed(self) -> bool:
        return self.decision is Decision.ALLOWED

    @property
    def is_possible(self) -> bool:
        """Allowed, or allowed if unresolved conditions hold."""
        return self.decision in (Decision.ALLOWED, Decision.INDETERMINATE)

    def evidence(self) -> list[Evidence]:
        return [m.to_evidence() for m in self.matches]

    def unknown_reasons(self) -> list[str]:
        seen: list[str] = []
        for m in self.matches:
            for r in m.reasons:
                if r not in seen:
                    seen.append(r)
        for r in self.reasons:
            if r not in seen:
                seen.append(r)
        return seen


@dataclass
class AssumeResult:
    role_arn: str
    identity: PrincipalIdentity
    decision: Decision
    trust: EvaluationResult
    identity_permission: EvaluationResult | None
    identity_permission_required: bool
    preconditions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_possible(self) -> bool:
        return self.decision in (Decision.ALLOWED, Decision.INDETERMINATE)

    def evidence(self) -> list[Evidence]:
        items = self.trust.evidence()
        if self.identity_permission is not None:
            items.extend(self.identity_permission.evidence())
        return items


def _grants_identity_directly(raw: Mapping[str, object], identity: PrincipalIdentity) -> bool:
    """True when a raw statement's ``Principal`` names everyone or the identity's own ARN.

    Naming the account root (or a bare account id) instead delegates to the account, which
    AWS treats differently: the identity then also needs an identity-based allow.
    """
    principal = raw.get("Principal")
    if principal == "*":
        return True
    entries: list[str] = []
    if isinstance(principal, Mapping):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, str):
            entries = [aws]
        elif isinstance(aws, list):
            entries = [e for e in aws if isinstance(e, str)]
    if "*" in entries:
        return True
    target = normalize_principal_arn(identity.arn)
    return any(
        not principal_entry_names_account(entry) and normalize_principal_arn(entry) == target
        for entry in entries
    )


class LimitationLog:
    """Deduplicated record of everything the evaluator could not decide."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str, str], int] = {}

    def record(self, kind: str, subject: str, reason: str = "") -> None:
        """Count one occurrence of ``kind`` for ``subject`` (a policy ARN or a statement
        label), with the optional ``reason`` kept separate so that labels containing
        colons never have to be parsed apart again."""
        key = (kind, subject, reason)
        self._entries[key] = self._entries.get(key, 0) + 1

    def entries(self) -> list[tuple[str, str, int]]:
        """``(kind, detail, count)`` triples, ``detail`` being ``subject: reason``."""
        return [
            (kind, f"{subject}: {reason}" if reason else subject, n)
            for (kind, subject, reason), n in sorted(self._entries.items())
        ]

    def by_kind(self, kind: str) -> list[tuple[str, str, int]]:
        """``(subject, reason, count)`` triples recorded under ``kind``."""
        return [
            (subject, reason, n)
            for (k, subject, reason), n in sorted(self._entries.items())
            if k == kind
        ]

    def __len__(self) -> int:
        return len(self._entries)


class PolicyEvaluator:
    """Answers "can principal P perform action A on resource R?" from a snapshot."""

    def __init__(self, env: Environment, limitations: LimitationLog | None = None) -> None:
        self.env = env
        # An empty log is falsy (it defines __len__), so test identity, not truthiness.
        self.limitations = limitations if limitations is not None else LimitationLog()
        self._identity_cache: dict[str, list[PolicyDocument]] = {}
        self._unresolved: dict[str, list[str]] = {}
        self._admin_cache: dict[str, tuple[Tri, list[PolicyRef]]] = {}

    # ------------------------------------------------------------------
    # policy resolution
    # ------------------------------------------------------------------
    def identity_policies(self, principal: Principal) -> list[PolicyDocument]:
        cached = self._identity_cache.get(principal.arn)
        if cached is not None:
            return cached
        docs: list[PolicyDocument] = list(principal.inline_policies.values())
        unresolved: list[str] = []
        docs.extend(self._resolve_attached(principal.attached_policy_arns, unresolved))
        if isinstance(principal, User):
            for group_name in principal.groups:
                group = self.env.group_by_name(group_name)
                if group is None:
                    continue
                docs.extend(group.inline_policies.values())
                docs.extend(self._resolve_attached(group.attached_policy_arns, unresolved))
        self._identity_cache[principal.arn] = docs
        self._unresolved[principal.arn] = unresolved
        return docs

    def _resolve_attached(self, arns: Iterable[str], unresolved: list[str]) -> list[PolicyDocument]:
        docs: list[PolicyDocument] = []
        for arn in arns:
            managed = self.env.managed_policy(arn)
            if managed is None:
                unresolved.append(arn)
                self.limitations.record("unresolved-policy", arn)
            else:
                docs.append(managed.document)
        return docs

    def unresolved_policies_for(self, principal: Principal) -> list[str]:
        self.identity_policies(principal)
        return list(self._unresolved.get(principal.arn, []))

    def boundary_policy(self, principal: Principal) -> tuple[PolicyDocument | None, str | None]:
        """Return ``(document, unresolved_arn)`` for the permissions boundary, if any."""
        arn = principal.permissions_boundary_arn
        if arn is None:
            return None, None
        managed = self.env.managed_policy(arn)
        if managed is None:
            self.limitations.record("unresolved-boundary", arn)
            return None, arn
        return managed.document, None

    # ------------------------------------------------------------------
    # request context
    # ------------------------------------------------------------------
    def request_context(
        self,
        identity: PrincipalIdentity,
        resource_arn: str | None = None,
        extra: Mapping[str, str | list[str] | None] | None = None,
    ) -> dict[str, str | list[str] | None]:
        ctx: dict[str, str | list[str] | None] = {}
        if identity.kind is IdentityKind.ANONYMOUS:
            ctx["aws:principalarn"] = None
            ctx["aws:principalaccount"] = None
            ctx["aws:principaltype"] = "Anonymous"
        else:
            ctx["aws:principalarn"] = identity.arn
            ctx["aws:principalaccount"] = identity.account_id
            if identity.kind is IdentityKind.USER:
                ctx["aws:principaltype"] = "User"
            elif identity.kind is IdentityKind.ROLE:
                ctx["aws:principaltype"] = "AssumedRole"
            elif identity.kind is IdentityKind.ACCOUNT:
                ctx["aws:principaltype"] = "Account"
        principal = self.env.principal(identity.arn)
        if isinstance(principal, User):
            ctx["aws:username"] = principal.name
        if principal is not None:
            for key, value in principal.tags.items():
                ctx[f"aws:principaltag/{key.lower()}"] = value
        if resource_arn is not None:
            account = account_of(resource_arn)
            bucket = self.env.bucket(resource_arn)
            if bucket is not None:
                account = bucket.account_id
                for key, value in bucket.tags.items():
                    ctx[f"aws:resourcetag/{key.lower()}"] = value
            if account:
                ctx["aws:resourceaccount"] = account
        if extra:
            for extra_key, extra_value in extra.items():
                ctx[extra_key.lower()] = extra_value
        return ctx

    # ------------------------------------------------------------------
    # core evaluation
    # ------------------------------------------------------------------
    def evaluate_documents(
        self,
        docs: Sequence[PolicyDocument],
        action: str,
        resource: str,
        context: RequestContext,
        *,
        layer: str,
        identity: PrincipalIdentity | None = None,
    ) -> tuple[Tri, Tri, list[StatementMatch]]:
        """Return ``(allow, deny, matches)`` for the statements in ``docs``."""
        allow = Tri.FALSE
        deny = Tri.FALSE
        matches: list[StatementMatch] = []
        variables = {k: v if isinstance(v, str) else None for k, v in context.items()}
        for doc in docs:
            # Only Version 2012-10-17 documents interpret ${...} policy variables.
            literal = doc.version != POLICY_VARIABLE_VERSION
            for statement in doc.statements:
                if not statement_action_matches(statement, action):
                    continue
                resource_match = statement_resource_matches(
                    statement, resource, variables, literal_variables=literal
                )
                if resource_match is Tri.FALSE:
                    continue
                reasons: list[str] = []
                if resource_match is Tri.UNKNOWN:
                    reasons.append(
                        "resource pattern contains a policy variable that cannot be resolved offline"
                    )
                    self.limitations.record("policy-variable", f"{doc.source} {statement.label()}")
                principal_match = Tri.TRUE
                if identity is not None:
                    principal_match = statement_principal_matches(statement, identity)
                    if principal_match is Tri.FALSE:
                        continue
                    if principal_match is Tri.UNKNOWN:
                        reasons.append(
                            "principal element cannot be matched to this identity offline"
                        )
                        self.limitations.record(
                            "principal-match", f"{doc.source} {statement.label()}"
                        )
                condition_result, condition_reasons = evaluate_conditions(
                    statement.conditions, context, literal_variables=literal
                )
                if condition_result is Tri.FALSE:
                    continue
                for reason in condition_reasons:
                    self.limitations.record(
                        "condition", f"{doc.source} {statement.label()}", reason
                    )
                reasons.extend(condition_reasons)
                applies = tri_and(resource_match, principal_match, condition_result)
                match = StatementMatch(
                    ref=doc.ref(statement),
                    effect=statement.effect,
                    result=applies,
                    layer=layer,
                    reasons=tuple(reasons),
                )
                matches.append(match)
                if statement.effect is Effect.ALLOW:
                    allow = tri_or(allow, applies)
                else:
                    deny = tri_or(deny, applies)
        return allow, deny, matches

    def evaluate(
        self,
        principal: Principal,
        action: str,
        resource: str,
        *,
        resource_policy: PolicyDocument | None = None,
        resource_account: str | None = None,
        extra_context: Mapping[str, str | list[str] | None] | None = None,
    ) -> EvaluationResult:
        """Evaluate whether ``principal`` may perform ``action`` on ``resource``."""
        identity = PrincipalIdentity.from_principal(principal)
        context = self.request_context(identity, resource, extra_context)
        docs = self.identity_policies(principal)
        result = EvaluationResult(principal.arn, action, resource, Decision.IMPLICIT_DENY)
        result.unresolved_policies = list(self._unresolved.get(principal.arn, []))

        allow_i, deny_i, matches = self.evaluate_documents(
            docs, action, resource, context, layer="identity"
        )
        result.matches.extend(matches)
        if result.unresolved_policies and allow_i is not Tri.TRUE:
            # A policy we could not see might grant the permission.
            allow_i = tri_or(allow_i, Tri.UNKNOWN)
            result.reasons.append(
                "attached policy document(s) not present in the snapshot: "
                + ", ".join(result.unresolved_policies)
            )
        if result.unresolved_policies and deny_i is not Tri.TRUE:
            deny_i = tri_or(deny_i, Tri.UNKNOWN)
        result.identity_allow, result.identity_deny = allow_i, deny_i

        boundary_doc, unresolved_boundary = self.boundary_policy(principal)
        boundary_allow: Tri | None = None
        boundary_deny = Tri.FALSE
        if boundary_doc is not None:
            boundary_allow, boundary_deny, b_matches = self.evaluate_documents(
                [boundary_doc], action, resource, context, layer="boundary"
            )
            result.matches.extend(b_matches)
        elif unresolved_boundary is not None:
            boundary_allow = Tri.UNKNOWN
            result.reasons.append(
                f"permissions boundary {unresolved_boundary} is not present in the snapshot"
            )
        result.boundary_allow = boundary_allow

        identity_effective = allow_i if boundary_allow is None else tri_and(allow_i, boundary_allow)

        resource_allow: Tri | None = None
        resource_deny: Tri | None = None
        r_matches: list[StatementMatch] = []
        if resource_policy is not None:
            resource_allow, resource_deny, r_matches = self.evaluate_documents(
                [resource_policy], action, resource, context, layer="resource", identity=identity
            )
            result.matches.extend(r_matches)
        result.resource_allow, result.resource_deny = resource_allow, resource_deny

        same_account = resource_account is None or resource_account == principal.account_id
        if resource_allow is None:
            allow = identity_effective
        elif same_account:
            # A same-account resource policy that names the principal (or everyone) grants on
            # its own and is not limited by a boundary. One that only names the account root
            # delegates to the account: the identity policy must still allow the action.
            direct = any(
                m.effect is Effect.ALLOW
                and m.result is not Tri.FALSE
                and _grants_identity_directly(m.ref.statement, identity)
                for m in r_matches
            )
            allow = tri_or(identity_effective, resource_allow if direct else Tri.FALSE)
        else:
            allow = tri_and(identity_effective, resource_allow)

        deny = tri_or(deny_i, boundary_deny, Tri.FALSE if resource_deny is None else resource_deny)

        if deny is Tri.TRUE:
            result.decision = Decision.EXPLICIT_DENY
        elif allow is Tri.FALSE:
            result.decision = Decision.IMPLICIT_DENY
        elif allow is Tri.TRUE and deny is Tri.FALSE:
            result.decision = Decision.ALLOWED
        else:
            result.decision = Decision.INDETERMINATE
            if deny is Tri.UNKNOWN:
                result.reasons.append("a Deny statement applies if its unresolved condition holds")
        return result

    # ------------------------------------------------------------------
    # higher-level questions
    # ------------------------------------------------------------------
    def evaluate_resource_policy(
        self,
        policy: PolicyDocument,
        identity: PrincipalIdentity,
        action: str,
        resource: str,
        *,
        layer: str = "resource",
        extra_context: Mapping[str, str | list[str] | None] | None = None,
    ) -> EvaluationResult:
        """Evaluate a resource-based policy on its own for an arbitrary identity.

        Used for callers whose identity policies are outside the snapshot (anonymous
        access, other accounts) and for trust policies.
        """
        context = self.request_context(identity, resource, extra_context)
        allow, deny, matches = self.evaluate_documents(
            [policy], action, resource, context, layer=layer, identity=identity
        )
        result = EvaluationResult(identity.arn, action, resource, Decision.IMPLICIT_DENY)
        result.matches = matches
        result.resource_allow, result.resource_deny = allow, deny
        if deny is Tri.TRUE:
            result.decision = Decision.EXPLICIT_DENY
        elif allow is Tri.FALSE:
            result.decision = Decision.IMPLICIT_DENY
        elif allow is Tri.TRUE and deny is Tri.FALSE:
            result.decision = Decision.ALLOWED
        else:
            result.decision = Decision.INDETERMINATE
        return result

    def evaluate_trust(
        self,
        role: Role,
        identity: PrincipalIdentity,
        extra_context: Mapping[str, str | list[str] | None] | None = None,
    ) -> EvaluationResult:
        """Evaluate the role's trust policy for ``identity`` calling ``sts:AssumeRole``."""
        return self.evaluate_resource_policy(
            role.trust_policy,
            identity,
            "sts:AssumeRole",
            role.arn,
            layer="trust",
            extra_context=extra_context,
        )

    def trust_names_identity_directly(self, role: Role, identity: PrincipalIdentity) -> bool:
        """True when an Allow statement names the identity's ARN (not just its account)."""
        target = normalize_principal_arn(identity.arn)
        for st in role.trust_policy.statements:
            if st.effect is not Effect.ALLOW or st.principal is None:
                continue
            for entry in st.principal.aws:
                if (
                    not principal_entry_names_account(entry)
                    and normalize_principal_arn(entry) == target
                ):
                    return True
        return False

    def can_assume(
        self,
        identity: PrincipalIdentity,
        role: Role,
        extra_context: Mapping[str, str | list[str] | None] | None = None,
    ) -> AssumeResult:
        """Combine the trust policy with the caller's identity permission.

        * Same account, trust names the principal's ARN: trust alone is sufficient.
        * Same account, trust names the account (``:root``): the caller also needs an
          identity-policy ``Allow`` for ``sts:AssumeRole`` on the role.
        * Cross account: the caller needs both; the external identity policy is
          outside the snapshot, so that half becomes a stated precondition.
        """
        trust = self.evaluate_trust(role, identity, extra_context)
        preconditions: list[str] = []
        notes: list[str] = []
        for reason in trust.unknown_reasons():
            preconditions.append(f"trust policy condition must hold: {reason}")

        same_account = identity.account_id == role.account_id
        local_principal = self.env.principal(identity.arn)
        permission_required = not (
            same_account and self.trust_names_identity_directly(role, identity)
        )
        identity_result: EvaluationResult | None = None
        permission: Tri
        if identity.kind is IdentityKind.ANONYMOUS:
            permission_required = False
            permission = Tri.TRUE
            notes.append("trust policy grants sts:AssumeRole to any AWS principal")
        elif not permission_required:
            permission = Tri.TRUE
            notes.append(
                "trust policy names the caller directly; no identity-policy permission is needed"
            )
        elif local_principal is not None:
            identity_result = self.evaluate(local_principal, "sts:AssumeRole", role.arn)
            if identity_result.decision is Decision.ALLOWED:
                permission = Tri.TRUE
            elif identity_result.decision is Decision.INDETERMINATE:
                permission = Tri.UNKNOWN
                for reason in identity_result.unknown_reasons():
                    preconditions.append(f"caller's sts:AssumeRole permission depends on: {reason}")
            else:
                permission = Tri.FALSE
        else:
            permission = Tri.UNKNOWN
            preconditions.append(
                f"a principal in account {identity.account_id or 'unknown'} must hold an identity-policy "
                "Allow for sts:AssumeRole on this role (that account's policies are outside the snapshot)"
            )

        if trust.decision is Decision.EXPLICIT_DENY:
            decision = Decision.EXPLICIT_DENY
        elif trust.decision is Decision.IMPLICIT_DENY or permission is Tri.FALSE:
            decision = Decision.IMPLICIT_DENY
        elif trust.decision is Decision.ALLOWED and permission is Tri.TRUE:
            decision = Decision.ALLOWED
        else:
            decision = Decision.INDETERMINATE
        if identity_result is not None and identity_result.decision is Decision.EXPLICIT_DENY:
            decision = Decision.EXPLICIT_DENY
        return AssumeResult(
            role_arn=role.arn,
            identity=identity,
            decision=decision,
            trust=trust,
            identity_permission=identity_result,
            identity_permission_required=permission_required,
            preconditions=preconditions,
            notes=notes,
        )

    def is_admin_equivalent(self, principal: Principal) -> tuple[Tri, list[PolicyRef]]:
        """Probe a set of high-impact actions on ``*``; TRUE when all are allowed."""
        cached = self._admin_cache.get(principal.arn)
        if cached is not None:
            return cached
        overall = Tri.TRUE
        refs: list[PolicyRef] = []
        for action in ADMIN_PROBE_ACTIONS:
            result = self.evaluate(principal, action, "*")
            if result.decision is Decision.ALLOWED:
                for m in result.allow_matches:
                    if m.result is Tri.TRUE and m.ref not in refs:
                        refs.append(m.ref)
            elif result.decision is Decision.INDETERMINATE:
                overall = tri_and(overall, Tri.UNKNOWN)
            else:
                overall = Tri.FALSE
                break
        if overall is Tri.FALSE:
            refs = []
        self._admin_cache[principal.arn] = (overall, refs)
        return overall, refs

    def principal_kind_label(self, principal: Principal) -> str:
        return "user" if principal.kind is PrincipalKind.USER else "role"
