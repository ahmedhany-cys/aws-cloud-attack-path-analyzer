"""Environment snapshot model: the inventory the analyzer reasons about.

A snapshot is produced either by the parser (from a synthetic fixture or exported
configuration) or by the optional read-only AWS adapter. Everything downstream
only sees this model, which keeps AWS API details out of the analysis engine.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

from attackpath.models.policy import PolicyDocument


class PrincipalKind(str, Enum):
    USER = "user"
    ROLE = "role"


class Sensitivity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class CoverageStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING = "missing"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AccessKey:
    key_id: str
    status: str
    created: str | None = None
    last_used: str | None = None


@dataclass
class User:
    name: str
    arn: str
    account_id: str
    path: str = "/"
    groups: list[str] = field(default_factory=list)
    inline_policies: dict[str, PolicyDocument] = field(default_factory=dict)
    attached_policy_arns: list[str] = field(default_factory=list)
    permissions_boundary_arn: str | None = None
    access_keys: list[AccessKey] = field(default_factory=list)
    mfa_enabled: bool | None = None
    console_access: bool | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def kind(self) -> PrincipalKind:
        return PrincipalKind.USER

    @property
    def active_access_keys(self) -> list[AccessKey]:
        return [k for k in self.access_keys if k.status.lower() == "active"]


@dataclass
class Group:
    name: str
    arn: str
    account_id: str
    path: str = "/"
    inline_policies: dict[str, PolicyDocument] = field(default_factory=dict)
    attached_policy_arns: list[str] = field(default_factory=list)


@dataclass
class Role:
    name: str
    arn: str
    account_id: str
    trust_policy: PolicyDocument
    path: str = "/"
    inline_policies: dict[str, PolicyDocument] = field(default_factory=dict)
    attached_policy_arns: list[str] = field(default_factory=list)
    permissions_boundary_arn: str | None = None
    description: str | None = None
    last_used: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def kind(self) -> PrincipalKind:
        return PrincipalKind.ROLE


Principal = User | Role


def principal_kind(principal: Principal) -> PrincipalKind:
    return principal.kind


@dataclass
class ManagedPolicy:
    arn: str
    name: str
    document: PolicyDocument
    is_aws_managed: bool = False
    attachment_count: int | None = None
    default_version_id: str | None = None


@dataclass(frozen=True)
class PublicAccessBlock:
    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False

    @property
    def fully_enabled(self) -> bool:
        return (
            self.block_public_acls
            and self.ignore_public_acls
            and self.block_public_policy
            and self.restrict_public_buckets
        )


@dataclass
class S3Bucket:
    name: str
    arn: str
    account_id: str
    region: str | None = None
    bucket_policy: PolicyDocument | None = None
    public_access_block: PublicAccessBlock | None = None
    acl_public_read: bool | None = None
    acl_public_write: bool | None = None
    encryption: str | None = None
    sensitivity: Sensitivity = Sensitivity.UNKNOWN
    description: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class LambdaFunction:
    name: str
    arn: str
    account_id: str
    role_arn: str | None
    region: str | None = None
    runtime: str | None = None
    resource_policy: PolicyDocument | None = None
    description: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class ExternalPrincipal:
    """A principal outside the analyzed account that appears in trust or resource policies."""

    arn: str
    account_id: str | None
    description: str | None = None
    known: bool = False


@dataclass(frozen=True)
class ServiceCoverage:
    status: CoverageStatus
    notes: tuple[str, ...] = ()


@dataclass
class Coverage:
    services: dict[str, ServiceCoverage] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def status_of(self, service: str) -> CoverageStatus:
        entry = self.services.get(service)
        return entry.status if entry else CoverageStatus.UNKNOWN

    @property
    def is_complete(self) -> bool:
        return bool(self.services) and all(
            s.status is CoverageStatus.COMPLETE for s in self.services.values()
        )

    def incomplete_services(self) -> list[tuple[str, ServiceCoverage]]:
        return [
            (name, cov)
            for name, cov in sorted(self.services.items())
            if cov.status is not CoverageStatus.COMPLETE
        ]


@dataclass
class Metadata:
    name: str = "unnamed environment"
    description: str | None = None
    synthetic: bool = False
    source: str = "fixture"
    generated_at: str | None = None
    generator: str | None = None
    regions: list[str] = field(default_factory=list)


@dataclass
class Environment:
    """A complete snapshot of the identities and resources under analysis."""

    account_id: str
    schema_version: str = "1.0"
    metadata: Metadata = field(default_factory=Metadata)
    coverage: Coverage = field(default_factory=Coverage)
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    managed_policies: list[ManagedPolicy] = field(default_factory=list)
    s3_buckets: list[S3Bucket] = field(default_factory=list)
    lambda_functions: list[LambdaFunction] = field(default_factory=list)
    external_principals: list[ExternalPrincipal] = field(default_factory=list)

    # ---- lookup helpers -------------------------------------------------
    def __post_init__(self) -> None:
        self._reindex()

    def _reindex(self) -> None:
        self._users_by_arn = {u.arn: u for u in self.users}
        self._roles_by_arn = {r.arn: r for r in self.roles}
        self._groups_by_name = {g.name: g for g in self.groups}
        self._groups_by_arn = {g.arn: g for g in self.groups}
        self._policies_by_arn = {p.arn: p for p in self.managed_policies}
        self._buckets_by_arn = {b.arn: b for b in self.s3_buckets}
        self._lambdas_by_arn = {f.arn: f for f in self.lambda_functions}

    def user(self, arn: str) -> User | None:
        return self._users_by_arn.get(arn)

    def role(self, arn: str) -> Role | None:
        return self._roles_by_arn.get(arn)

    def group_by_name(self, name: str) -> Group | None:
        return self._groups_by_name.get(name)

    def group(self, arn: str) -> Group | None:
        return self._groups_by_arn.get(arn)

    def managed_policy(self, arn: str) -> ManagedPolicy | None:
        return self._policies_by_arn.get(arn)

    def bucket(self, arn: str) -> S3Bucket | None:
        return self._buckets_by_arn.get(arn)

    def lambda_function(self, arn: str) -> LambdaFunction | None:
        return self._lambdas_by_arn.get(arn)

    def principal(self, arn: str) -> Principal | None:
        return self._users_by_arn.get(arn) or self._roles_by_arn.get(arn)

    def principals(self) -> Iterator[Principal]:
        yield from self.users
        yield from self.roles

    @property
    def principal_count(self) -> int:
        return len(self.users) + len(self.roles)

    @property
    def resource_count(self) -> int:
        return len(self.s3_buckets) + len(self.lambda_functions)

    def roles_used_by_lambdas(self) -> dict[str, list[LambdaFunction]]:
        result: dict[str, list[LambdaFunction]] = {}
        for fn in self.lambda_functions:
            if fn.role_arn:
                result.setdefault(fn.role_arn, []).append(fn)
        return result

    def summary(self) -> dict[str, int]:
        return {
            "users": len(self.users),
            "groups": len(self.groups),
            "roles": len(self.roles),
            "managed_policies": len(self.managed_policies),
            "s3_buckets": len(self.s3_buckets),
            "lambda_functions": len(self.lambda_functions),
            "external_principals": len(self.external_principals),
        }
