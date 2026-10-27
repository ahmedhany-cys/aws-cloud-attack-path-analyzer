"""Normalized representation of IAM policy documents.

The parser turns the many syntactic variants AWS accepts (string-or-list fields,
``NotAction``, ``NotResource``, principal maps, nested condition maps) into the
immutable structures below so the evaluator only has to reason about one shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_SET_PREFIXES = ("ForAnyValue:", "ForAllValues:")
_IF_EXISTS = "IfExists"


class Effect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass(frozen=True)
class Condition:
    """One ``operator -> key -> values`` entry of a ``Condition`` block."""

    operator: str
    key: str
    values: tuple[str, ...]

    @property
    def set_operator(self) -> str | None:
        for prefix in _SET_PREFIXES:
            if self.operator.startswith(prefix):
                return prefix[:-1]
        return None

    @property
    def if_exists(self) -> bool:
        return self.operator.endswith(_IF_EXISTS)

    @property
    def base_operator(self) -> str:
        op = self.operator
        for prefix in _SET_PREFIXES:
            op = op.removeprefix(prefix)
        return op.removesuffix(_IF_EXISTS)

    def describe(self) -> str:
        values = ", ".join(self.values)
        return f"{self.operator} {self.key} = [{values}]"


@dataclass(frozen=True)
class PrincipalSpec:
    """The ``Principal`` or ``NotPrincipal`` element of a resource-based policy."""

    wildcard: bool = False
    aws: tuple[str, ...] = ()
    service: tuple[str, ...] = ()
    federated: tuple[str, ...] = ()
    canonical_user: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.wildcard or self.aws or self.service or self.federated or self.canonical_user
        )

    @property
    def is_anonymous(self) -> bool:
        """True when the element grants to everyone (``"*"`` or ``{"AWS": "*"}``)."""
        return self.wildcard or "*" in self.aws

    def describe(self) -> str:
        if self.wildcard:
            return "*"
        parts: list[str] = []
        if self.aws:
            parts.append("AWS=" + ",".join(self.aws))
        if self.service:
            parts.append("Service=" + ",".join(self.service))
        if self.federated:
            parts.append("Federated=" + ",".join(self.federated))
        if self.canonical_user:
            parts.append("CanonicalUser=" + ",".join(self.canonical_user))
        return "; ".join(parts) or "<none>"


@dataclass(frozen=True)
class Statement:
    """A single normalized policy statement."""

    index: int
    effect: Effect
    sid: str | None = None
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    principal: PrincipalSpec | None = None
    not_principal: PrincipalSpec | None = None
    conditions: tuple[Condition, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def uses_not_action(self) -> bool:
        return bool(self.not_actions)

    @property
    def uses_not_resource(self) -> bool:
        return bool(self.not_resources)

    @property
    def has_resource_element(self) -> bool:
        return bool(self.resources or self.not_resources)

    @property
    def has_principal_element(self) -> bool:
        return self.principal is not None or self.not_principal is not None

    @property
    def is_allow(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def is_deny(self) -> bool:
        return self.effect is Effect.DENY

    def label(self) -> str:
        if self.sid:
            return f"statement[{self.index}] (Sid: {self.sid})"
        return f"statement[{self.index}]"


@dataclass(frozen=True)
class PolicyDocument:
    """A parsed policy document with a human-readable ``source`` for evidence."""

    source: str
    statements: tuple[Statement, ...]
    version: str | None = None
    policy_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def ref(self, statement: Statement) -> PolicyRef:
        return PolicyRef(
            source=self.source,
            statement_index=statement.index,
            sid=statement.sid,
            effect=statement.effect.value,
            statement=dict(statement.raw),
        )


@dataclass(frozen=True)
class PolicyRef:
    """Pointer to one statement of one policy, attached to findings as evidence."""

    source: str
    statement_index: int
    sid: str | None
    effect: str
    statement: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def describe(self) -> str:
        sid = f" Sid={self.sid}" if self.sid else ""
        return f"{self.source} statement[{self.statement_index}]{sid} ({self.effect})"
