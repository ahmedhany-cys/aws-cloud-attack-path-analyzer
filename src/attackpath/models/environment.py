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


#: CIDR blocks that mean "every address on the internet".
PUBLIC_IPV4_CIDR = "0.0.0.0/0"
PUBLIC_IPV6_CIDR = "::/0"

#: Ports whose exposure to the internet is a management or data-plane risk in itself.
MANAGEMENT_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    6379: "Redis",
    8500: "Consul",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class IngressRule:
    """One inbound rule of a security group."""

    protocol: str  # tcp | udp | icmp | icmpv6 | all
    from_port: int | None = None  # None: every port of the protocol
    to_port: int | None = None
    cidrs: tuple[str, ...] = ()
    ipv6_cidrs: tuple[str, ...] = ()
    source_groups: tuple[str, ...] = ()
    description: str | None = None

    @property
    def is_public(self) -> bool:
        return PUBLIC_IPV4_CIDR in self.cidrs or PUBLIC_IPV6_CIDR in self.ipv6_cidrs

    @property
    def portless(self) -> bool:
        """ICMP rules carry type/code, not ports."""
        return self.protocol in ("icmp", "icmpv6")

    @property
    def all_ports(self) -> bool:
        """Every TCP/UDP port: protocol ``all``, or a TCP/UDP rule without a (full) range."""
        if self.protocol == "all":
            return True
        if self.portless:
            return False
        if self.from_port is None or self.to_port is None:
            return True
        return self.from_port == 0 and self.to_port == 65535

    def ports(self) -> list[int]:
        """The individual ports of a bounded range (empty when every port is covered)."""
        if self.all_ports or self.from_port is None or self.to_port is None:
            return []
        return list(range(self.from_port, min(self.to_port, self.from_port + 1023) + 1))

    def management_ports(self) -> dict[int, str]:
        """Management/database ports the rule exposes (they are TCP services)."""
        if self.protocol not in ("tcp", "all"):
            return {}
        if self.all_ports:
            return dict(MANAGEMENT_PORTS)
        if self.from_port is None or self.to_port is None:
            return {}
        return {p: n for p, n in MANAGEMENT_PORTS.items() if self.from_port <= p <= self.to_port}

    def describe(self) -> str:
        if self.protocol == "all":
            span = "all ports"
        elif self.portless:
            span = f"{self.protocol} (all types)"
        elif self.all_ports:
            span = f"{self.protocol} all ports"
        elif self.from_port == self.to_port:
            span = f"{self.protocol} {self.from_port}"
        else:
            span = f"{self.protocol} {self.from_port}-{self.to_port}"
        sources = ", ".join([*self.cidrs, *self.ipv6_cidrs, *self.source_groups]) or "no source"
        return f"{span} from {sources}"


@dataclass
class SecurityGroup:
    group_id: str
    name: str | None = None
    vpc_id: str | None = None
    description: str | None = None
    ingress: list[IngressRule] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def public_ingress(self) -> list[IngressRule]:
        return [rule for rule in self.ingress if rule.is_public]


@dataclass
class Ec2Instance:
    instance_id: str
    arn: str
    account_id: str
    region: str | None = None
    name: str | None = None
    state: str = "running"
    public_ip: str | None = None
    public_dns: str | None = None
    subnet_id: str | None = None
    vpc_id: str | None = None
    internet_facing: bool | None = None  # does the subnet route to an internet gateway?
    security_group_ids: list[str] = field(default_factory=list)
    role_arn: str | None = None
    instance_profile_arn: str | None = None
    imdsv2_required: bool | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.instance_id

    @property
    def is_running(self) -> bool:
        return self.state.lower() == "running"


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
    security_groups: list[SecurityGroup] = field(default_factory=list)
    ec2_instances: list[Ec2Instance] = field(default_factory=list)
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
        self._groups_by_id = {g.group_id: g for g in self.security_groups}
        self._instances_by_arn = {i.arn: i for i in self.ec2_instances}

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

    def security_group(self, group_id: str) -> SecurityGroup | None:
        return self._groups_by_id.get(group_id)

    def instance(self, arn: str) -> Ec2Instance | None:
        return self._instances_by_arn.get(arn)

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
        return len(self.s3_buckets) + len(self.lambda_functions) + len(self.ec2_instances)

    def roles_used_by_lambdas(self) -> dict[str, list[LambdaFunction]]:
        result: dict[str, list[LambdaFunction]] = {}
        for fn in self.lambda_functions:
            if fn.role_arn:
                result.setdefault(fn.role_arn, []).append(fn)
        return result

    def roles_used_by_instances(self) -> dict[str, list[Ec2Instance]]:
        result: dict[str, list[Ec2Instance]] = {}
        for instance in self.ec2_instances:
            if instance.role_arn:
                result.setdefault(instance.role_arn, []).append(instance)
        return result

    def summary(self) -> dict[str, int]:
        return {
            "users": len(self.users),
            "groups": len(self.groups),
            "roles": len(self.roles),
            "managed_policies": len(self.managed_policies),
            "s3_buckets": len(self.s3_buckets),
            "lambda_functions": len(self.lambda_functions),
            "ec2_instances": len(self.ec2_instances),
            "security_groups": len(self.security_groups),
            "external_principals": len(self.external_principals),
        }
