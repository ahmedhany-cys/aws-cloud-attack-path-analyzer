"""Principal matching for trust and resource-based policies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from attackpath.models.arn import account_of, is_account_root, normalize_principal_arn
from attackpath.models.environment import Principal, PrincipalKind
from attackpath.models.policy import PrincipalSpec, Statement
from attackpath.tri import Tri, tri_not


class IdentityKind(str, Enum):
    USER = "user"
    ROLE = "role"
    ACCOUNT = "account"
    ANONYMOUS = "anonymous"
    SERVICE = "service"
    FEDERATED = "federated"


@dataclass(frozen=True)
class PrincipalIdentity:
    """The caller whose access is being evaluated."""

    arn: str
    account_id: str | None
    kind: IdentityKind

    @classmethod
    def from_principal(cls, principal: Principal) -> PrincipalIdentity:
        kind = IdentityKind.USER if principal.kind is PrincipalKind.USER else IdentityKind.ROLE
        return cls(arn=principal.arn, account_id=principal.account_id, kind=kind)

    @classmethod
    def account(cls, account_id: str) -> PrincipalIdentity:
        return cls(
            arn=f"arn:aws:iam::{account_id}:root", account_id=account_id, kind=IdentityKind.ACCOUNT
        )

    @classmethod
    def anonymous(cls) -> PrincipalIdentity:
        return cls(arn="*", account_id=None, kind=IdentityKind.ANONYMOUS)

    @classmethod
    def service(cls, name: str) -> PrincipalIdentity:
        return cls(arn=name.lower(), account_id=None, kind=IdentityKind.SERVICE)

    @classmethod
    def external(cls, arn: str) -> PrincipalIdentity:
        if arn == "*":
            return cls.anonymous()
        account = account_of(arn)
        if is_account_root(arn):
            return cls.account(account or "")
        kind = IdentityKind.ROLE if ":role/" in arn else IdentityKind.USER
        return cls(arn=arn, account_id=account, kind=kind)

    @property
    def is_iam_identity(self) -> bool:
        return self.kind in (IdentityKind.USER, IdentityKind.ROLE)


def principal_matches(spec: PrincipalSpec, identity: PrincipalIdentity) -> Tri:
    """Whether a ``Principal`` element covers ``identity``."""
    if spec.wildcard:
        return Tri.TRUE
    result = Tri.FALSE
    for entry in spec.aws:
        if entry == "*":
            return Tri.TRUE
        if identity.kind is IdentityKind.ANONYMOUS:
            continue
        if is_account_root(entry):
            if (
                identity.account_id
                and account_of(entry) == identity.account_id
                and (identity.is_iam_identity or identity.kind is IdentityKind.ACCOUNT)
            ):
                return Tri.TRUE
            continue
        if normalize_principal_arn(entry) == normalize_principal_arn(identity.arn):
            return Tri.TRUE
        if identity.kind is IdentityKind.ACCOUNT and account_of(entry) == identity.account_id:
            # "a principal of account X" might be the specifically named one.
            result = Tri.UNKNOWN
    if identity.kind is IdentityKind.SERVICE and any(
        s.lower() == identity.arn for s in spec.service
    ):
        return Tri.TRUE
    if identity.kind is IdentityKind.FEDERATED and any(f == identity.arn for f in spec.federated):
        return Tri.TRUE
    if spec.canonical_user and identity.is_iam_identity:
        # Canonical user ids cannot be mapped to IAM identities offline.
        result = Tri.UNKNOWN
    return result


def statement_principal_matches(statement: Statement, identity: PrincipalIdentity) -> Tri:
    if statement.principal is not None:
        return principal_matches(statement.principal, identity)
    if statement.not_principal is not None:
        return tri_not(principal_matches(statement.not_principal, identity))
    return Tri.FALSE


def principal_entry_names_account(entry: str) -> bool:
    """True for ``arn:aws:iam::123456789012:root`` or a bare account id."""
    return is_account_root(entry)
