"""Strict parser for environment snapshot documents (see ``docs/input-format.md``)."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

from attackpath.config import Limits
from attackpath.exceptions import InputError, LimitExceededError
from attackpath.models.arn import account_of, is_account_id, parse_arn
from attackpath.models.environment import (
    AccessKey,
    Coverage,
    CoverageStatus,
    Ec2Instance,
    Environment,
    ExternalPrincipal,
    Group,
    IngressRule,
    LambdaFunction,
    ManagedPolicy,
    Metadata,
    PublicAccessBlock,
    Role,
    S3Bucket,
    SecurityGroup,
    Sensitivity,
    ServiceCoverage,
    User,
)
from attackpath.models.policy import PolicyDocument
from attackpath.parser.policy_parser import parse_policy_document

SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0"})
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "metadata",
        "account_id",
        "coverage",
        "users",
        "groups",
        "roles",
        "managed_policies",
        "s3_buckets",
        "lambda_functions",
        "security_groups",
        "ec2_instances",
        "external_principals",
    }
)
_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6", "all"})
_PORTLESS_PROTOCOLS = frozenset({"icmp", "icmpv6", "all"})


def parse_environment(
    data: Any,
    source: str,
    *,
    limits: Limits | None = None,
    warnings: list[str] | None = None,
) -> Environment:
    """Validate and convert a decoded snapshot document into an :class:`Environment`."""
    limits = limits or Limits()
    warnings = warnings if warnings is not None else []
    if not isinstance(data, Mapping):
        raise InputError(f"{source}: snapshot must be a JSON object")

    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise InputError(
            f"{source}: unsupported top-level element(s): {', '.join(sorted(unknown))}"
        )

    schema_version = _opt_str(data, "schema_version", source) or "1.0"
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise InputError(
            f"{source}: unsupported schema_version {schema_version!r} "
            f"(supported: {', '.join(sorted(SUPPORTED_SCHEMA_VERSIONS))})"
        )

    account_id = _req_str(data, "account_id", source)
    if not is_account_id(account_id):
        raise InputError(f"{source}: account_id must be a 12-digit string")

    metadata = _parse_metadata(data.get("metadata"), source)
    coverage = _parse_coverage(data.get("coverage"), source)

    users = [
        _parse_user(item, f"{source}.users[{i}]", account_id, warnings)
        for i, item in enumerate(_opt_list(data, "users", source))
    ]
    groups = [
        _parse_group(item, f"{source}.groups[{i}]", account_id, warnings)
        for i, item in enumerate(_opt_list(data, "groups", source))
    ]
    roles = [
        _parse_role(item, f"{source}.roles[{i}]", account_id, warnings)
        for i, item in enumerate(_opt_list(data, "roles", source))
    ]
    managed_policies = [
        _parse_managed_policy(item, f"{source}.managed_policies[{i}]", warnings)
        for i, item in enumerate(_opt_list(data, "managed_policies", source))
    ]
    buckets = [
        _parse_bucket(item, f"{source}.s3_buckets[{i}]", account_id, warnings)
        for i, item in enumerate(_opt_list(data, "s3_buckets", source))
    ]
    functions = [
        _parse_lambda(item, f"{source}.lambda_functions[{i}]", account_id, warnings)
        for i, item in enumerate(_opt_list(data, "lambda_functions", source))
    ]
    security_groups = [
        _parse_security_group(item, f"{source}.security_groups[{i}]")
        for i, item in enumerate(_opt_list(data, "security_groups", source))
    ]
    instances = [
        _parse_instance(item, f"{source}.ec2_instances[{i}]", account_id)
        for i, item in enumerate(_opt_list(data, "ec2_instances", source))
    ]
    externals = [
        _parse_external(item, f"{source}.external_principals[{i}]")
        for i, item in enumerate(_opt_list(data, "external_principals", source))
    ]

    if len(users) + len(roles) > limits.max_principals:
        raise LimitExceededError(
            f"{source}: {len(users) + len(roles)} principals exceed the limit of {limits.max_principals}"
        )
    resources = len(buckets) + len(functions) + len(instances)
    if resources > limits.max_resources:
        raise LimitExceededError(
            f"{source}: {resources} resources exceed the limit of {limits.max_resources}"
        )

    _reject_duplicates([u.arn for u in users], "users", source)
    _reject_duplicates([g.name for g in groups], "groups", source)
    _reject_duplicates([r.arn for r in roles], "roles", source)
    _reject_duplicates([p.arn for p in managed_policies], "managed_policies", source)
    _reject_duplicates([b.arn for b in buckets], "s3_buckets", source)
    _reject_duplicates([f.arn for f in functions], "lambda_functions", source)
    _reject_duplicates([g.group_id for g in security_groups], "security_groups", source)
    _reject_duplicates([i.arn for i in instances], "ec2_instances", source)

    group_names = {g.name for g in groups}
    for user in users:
        for name in user.groups:
            if name not in group_names:
                warnings.append(f"{source}: user {user.name} references unknown group {name!r}")
    security_group_ids = {g.group_id for g in security_groups}
    for instance in instances:
        for group_id in instance.security_group_ids:
            if group_id not in security_group_ids:
                warnings.append(
                    f"{source}: instance {instance.instance_id} references unknown security "
                    f"group {group_id!r}; its network exposure cannot be determined"
                )

    return Environment(
        account_id=account_id,
        schema_version=schema_version,
        metadata=metadata,
        coverage=coverage,
        users=users,
        groups=groups,
        roles=roles,
        managed_policies=managed_policies,
        s3_buckets=buckets,
        lambda_functions=functions,
        security_groups=security_groups,
        ec2_instances=instances,
        external_principals=externals,
    )


# ---------------------------------------------------------------------------
# section parsers
# ---------------------------------------------------------------------------


def _parse_metadata(raw: Any, source: str) -> Metadata:
    if raw is None:
        return Metadata()
    where = f"{source}.metadata"
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    return Metadata(
        name=_opt_str(raw, "name", where) or "unnamed environment",
        description=_opt_str(raw, "description", where),
        synthetic=_opt_bool(raw, "synthetic", where) or False,
        source=_opt_str(raw, "source", where) or "fixture",
        generated_at=_opt_str(raw, "generated_at", where),
        generator=_opt_str(raw, "generator", where),
        regions=list(_opt_str_list(raw, "regions", where)),
    )


def _parse_coverage(raw: Any, source: str) -> Coverage:
    if raw is None:
        return Coverage()
    where = f"{source}.coverage"
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    services: dict[str, ServiceCoverage] = {}
    services_raw = raw.get("services", {})
    if not isinstance(services_raw, Mapping):
        raise InputError(f"{where}.services: must be an object")
    for name, entry in services_raw.items():
        if not isinstance(name, str):
            raise InputError(f"{where}.services: service names must be strings")
        if isinstance(entry, str):
            services[name] = ServiceCoverage(
                status=_coverage_status(entry, f"{where}.services.{name}")
            )
        elif isinstance(entry, Mapping):
            status = _coverage_status(
                _req_str(entry, "status", f"{where}.services.{name}"), f"{where}.services.{name}"
            )
            notes = tuple(_opt_str_list(entry, "notes", f"{where}.services.{name}"))
            services[name] = ServiceCoverage(status=status, notes=notes)
        else:
            raise InputError(f"{where}.services.{name}: must be a status string or an object")
    return Coverage(services=services, notes=list(_opt_str_list(raw, "notes", where)))


def _coverage_status(value: str, where: str) -> CoverageStatus:
    try:
        return CoverageStatus(value.lower())
    except ValueError as exc:
        valid = ", ".join(s.value for s in CoverageStatus)
        raise InputError(
            f"{where}: invalid coverage status {value!r} (expected one of {valid})"
        ) from exc


def _parse_user(raw: Any, where: str, account_id: str, warnings: list[str]) -> User:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    name = _req_str(raw, "name", where)
    path = _opt_str(raw, "path", where) or "/"
    arn = _principal_arn(raw, where, account_id, "user", name, path)
    keys_raw = _opt_list(raw, "access_keys", where)
    keys: list[AccessKey] = []
    for i, key in enumerate(keys_raw):
        kw = f"{where}.access_keys[{i}]"
        if not isinstance(key, Mapping):
            raise InputError(f"{kw}: must be an object")
        keys.append(
            AccessKey(
                key_id=_req_str(key, "key_id", kw),
                status=_opt_str(key, "status", kw) or "Active",
                created=_opt_str(key, "created", kw),
                last_used=_opt_str(key, "last_used", kw),
            )
        )
    return User(
        name=name,
        arn=arn,
        account_id=account_of(arn) or account_id,
        path=path,
        groups=list(_opt_str_list(raw, "groups", where)),
        inline_policies=_parse_inline_policies(raw, where, f"inline:{arn}", warnings),
        attached_policy_arns=list(_opt_str_list(raw, "attached_policies", where)),
        permissions_boundary_arn=_opt_str(raw, "permissions_boundary", where),
        access_keys=keys,
        mfa_enabled=_opt_bool(raw, "mfa_enabled", where),
        console_access=_opt_bool(raw, "console_access", where),
        tags=_opt_str_dict(raw, "tags", where),
    )


def _parse_group(raw: Any, where: str, account_id: str, warnings: list[str]) -> Group:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    name = _req_str(raw, "name", where)
    path = _opt_str(raw, "path", where) or "/"
    arn = _principal_arn(raw, where, account_id, "group", name, path)
    return Group(
        name=name,
        arn=arn,
        account_id=account_of(arn) or account_id,
        path=path,
        inline_policies=_parse_inline_policies(raw, where, f"inline:{arn}", warnings),
        attached_policy_arns=list(_opt_str_list(raw, "attached_policies", where)),
    )


def _parse_role(raw: Any, where: str, account_id: str, warnings: list[str]) -> Role:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    name = _req_str(raw, "name", where)
    path = _opt_str(raw, "path", where) or "/"
    arn = _principal_arn(raw, where, account_id, "role", name, path)
    if "trust_policy" not in raw:
        raise InputError(f"{where}: role {name!r} is missing trust_policy")
    trust = parse_policy_document(raw["trust_policy"], f"trust:{arn}", warnings=warnings)
    for st in trust.statements:
        if not st.has_principal_element:
            raise InputError(f"{where}: trust policy {st.label()} has no Principal element")
    return Role(
        name=name,
        arn=arn,
        account_id=account_of(arn) or account_id,
        trust_policy=trust,
        path=path,
        inline_policies=_parse_inline_policies(raw, where, f"inline:{arn}", warnings),
        attached_policy_arns=list(_opt_str_list(raw, "attached_policies", where)),
        permissions_boundary_arn=_opt_str(raw, "permissions_boundary", where),
        description=_opt_str(raw, "description", where),
        last_used=_opt_str(raw, "last_used", where),
        tags=_opt_str_dict(raw, "tags", where),
    )


def _parse_managed_policy(raw: Any, where: str, warnings: list[str]) -> ManagedPolicy:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    arn = _req_str(raw, "arn", where)
    parsed = parse_arn(arn)
    if parsed is None or parsed.service != "iam" or parsed.resource_type != "policy":
        raise InputError(f"{where}: {arn!r} is not an IAM managed policy ARN")
    name = _opt_str(raw, "name", where) or parsed.resource_name.rsplit("/", 1)[-1]
    if "document" not in raw:
        raise InputError(f"{where}: managed policy {arn} is missing its document")
    document = parse_policy_document(raw["document"], f"managed:{arn}", warnings=warnings)
    is_aws = _opt_bool(raw, "is_aws_managed", where)
    if is_aws is None:
        is_aws = parsed.account == "aws"
    return ManagedPolicy(
        arn=arn,
        name=name,
        document=document,
        is_aws_managed=is_aws,
        attachment_count=_opt_int(raw, "attachment_count", where),
        default_version_id=_opt_str(raw, "default_version_id", where),
    )


def _parse_bucket(raw: Any, where: str, account_id: str, warnings: list[str]) -> S3Bucket:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    name = _req_str(raw, "name", where)
    arn = _opt_str(raw, "arn", where) or f"arn:aws:s3:::{name}"
    parsed = parse_arn(arn)
    if parsed is None or parsed.service != "s3":
        raise InputError(f"{where}: {arn!r} is not an S3 bucket ARN")
    policy_raw = raw.get("bucket_policy")
    policy = (
        parse_policy_document(policy_raw, f"bucket-policy:{arn}", warnings=warnings)
        if policy_raw is not None
        else None
    )
    if policy is not None:
        for st in policy.statements:
            if not st.has_principal_element:
                raise InputError(f"{where}: bucket policy {st.label()} has no Principal element")
    pab_raw = raw.get("public_access_block")
    pab: PublicAccessBlock | None = None
    if pab_raw is not None:
        pw = f"{where}.public_access_block"
        if not isinstance(pab_raw, Mapping):
            raise InputError(f"{pw}: must be an object")
        pab = PublicAccessBlock(
            block_public_acls=_opt_bool(pab_raw, "block_public_acls", pw) or False,
            ignore_public_acls=_opt_bool(pab_raw, "ignore_public_acls", pw) or False,
            block_public_policy=_opt_bool(pab_raw, "block_public_policy", pw) or False,
            restrict_public_buckets=_opt_bool(pab_raw, "restrict_public_buckets", pw) or False,
        )
    sensitivity_raw = _opt_str(raw, "sensitivity", where)
    try:
        sensitivity = (
            Sensitivity(sensitivity_raw.lower()) if sensitivity_raw else Sensitivity.UNKNOWN
        )
    except ValueError as exc:
        raise InputError(f"{where}: invalid sensitivity {sensitivity_raw!r}") from exc
    return S3Bucket(
        name=name,
        arn=arn,
        account_id=_opt_str(raw, "account_id", where) or account_id,
        region=_opt_str(raw, "region", where),
        bucket_policy=policy,
        public_access_block=pab,
        acl_public_read=_opt_bool(raw, "acl_public_read", where),
        acl_public_write=_opt_bool(raw, "acl_public_write", where),
        encryption=_opt_str(raw, "encryption", where),
        sensitivity=sensitivity,
        description=_opt_str(raw, "description", where),
        tags=_opt_str_dict(raw, "tags", where),
    )


def _parse_lambda(raw: Any, where: str, account_id: str, warnings: list[str]) -> LambdaFunction:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    name = _req_str(raw, "name", where)
    region = _opt_str(raw, "region", where)
    arn = (
        _opt_str(raw, "arn", where)
        or f"arn:aws:lambda:{region or 'us-east-1'}:{account_id}:function:{name}"
    )
    parsed = parse_arn(arn)
    if parsed is None or parsed.service != "lambda":
        raise InputError(f"{where}: {arn!r} is not a Lambda function ARN")
    policy_raw = raw.get("resource_policy")
    policy = (
        parse_policy_document(policy_raw, f"resource-policy:{arn}", warnings=warnings)
        if policy_raw is not None
        else None
    )
    role_arn = _opt_str(raw, "role_arn", where)
    if role_arn is not None and parse_arn(role_arn) is None:
        raise InputError(f"{where}: role_arn {role_arn!r} is not an ARN")
    return LambdaFunction(
        name=name,
        arn=arn,
        account_id=parsed.account or account_id,
        role_arn=role_arn,
        region=region or parsed.region or None,
        runtime=_opt_str(raw, "runtime", where),
        resource_policy=policy,
        description=_opt_str(raw, "description", where),
        tags=_opt_str_dict(raw, "tags", where),
    )


def _parse_security_group(raw: Any, where: str) -> SecurityGroup:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    group_id = _req_str(raw, "group_id", where)
    rules = [
        _parse_ingress_rule(item, f"{where}.ingress[{i}]")
        for i, item in enumerate(_opt_list(raw, "ingress", where))
    ]
    return SecurityGroup(
        group_id=group_id,
        name=_opt_str(raw, "name", where),
        vpc_id=_opt_str(raw, "vpc_id", where),
        description=_opt_str(raw, "description", where),
        ingress=rules,
        tags=_opt_str_dict(raw, "tags", where),
    )


def _parse_ingress_rule(raw: Any, where: str) -> IngressRule:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    protocol_raw = _opt_str(raw, "protocol", where) or "tcp"
    protocol = "all" if protocol_raw == "-1" else protocol_raw.lower()
    if protocol not in _PROTOCOLS:
        raise InputError(
            f"{where}: unsupported protocol {protocol_raw!r} (expected tcp, udp, icmp, icmpv6 or all)"
        )
    from_port = _opt_int(raw, "from_port", where)
    to_port = _opt_int(raw, "to_port", where)
    if (from_port is None) != (to_port is None):
        raise InputError(f"{where}: from_port and to_port must be given together")
    if from_port is not None and to_port is not None:
        if not (0 <= from_port <= 65535 and 0 <= to_port <= 65535):
            raise InputError(f"{where}: ports must be between 0 and 65535")
        if from_port > to_port:
            raise InputError(f"{where}: from_port must not exceed to_port")
    if protocol in _PORTLESS_PROTOCOLS:
        from_port = to_port = None
    cidrs = _opt_str_list(raw, "cidrs", where)
    ipv6_cidrs = _opt_str_list(raw, "ipv6_cidrs", where)
    for cidr in (*cidrs, *ipv6_cidrs):
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise InputError(f"{where}: {cidr!r} is not a valid CIDR block") from exc
    source_groups = _opt_str_list(raw, "source_groups", where)
    if not (cidrs or ipv6_cidrs or source_groups):
        raise InputError(f"{where}: an ingress rule needs cidrs, ipv6_cidrs or source_groups")
    return IngressRule(
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        cidrs=tuple(cidrs),
        ipv6_cidrs=tuple(ipv6_cidrs),
        source_groups=tuple(source_groups),
        description=_opt_str(raw, "description", where),
    )


def _parse_instance(raw: Any, where: str, account_id: str) -> Ec2Instance:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    instance_id = _req_str(raw, "instance_id", where)
    region = _opt_str(raw, "region", where)
    arn = (
        _opt_str(raw, "arn", where)
        or f"arn:aws:ec2:{region or 'us-east-1'}:{account_id}:instance/{instance_id}"
    )
    parsed = parse_arn(arn)
    if parsed is None or parsed.service != "ec2":
        raise InputError(f"{where}: {arn!r} is not an EC2 instance ARN")
    role_arn = _opt_str(raw, "role_arn", where)
    if role_arn is not None and parse_arn(role_arn) is None:
        raise InputError(f"{where}: role_arn {role_arn!r} is not an ARN")
    public_ip = _opt_str(raw, "public_ip", where)
    if public_ip is not None:
        try:
            ipaddress.ip_address(public_ip)
        except ValueError as exc:
            raise InputError(f"{where}: public_ip {public_ip!r} is not an IP address") from exc
    return Ec2Instance(
        instance_id=instance_id,
        arn=arn,
        account_id=parsed.account or account_id,
        region=region or parsed.region or None,
        name=_opt_str(raw, "name", where),
        state=(_opt_str(raw, "state", where) or "running").lower(),
        public_ip=public_ip,
        public_dns=_opt_str(raw, "public_dns", where),
        subnet_id=_opt_str(raw, "subnet_id", where),
        vpc_id=_opt_str(raw, "vpc_id", where),
        internet_facing=_opt_bool(raw, "internet_facing", where),
        security_group_ids=list(_opt_str_list(raw, "security_groups", where)),
        role_arn=role_arn,
        instance_profile_arn=_opt_str(raw, "instance_profile_arn", where),
        imdsv2_required=_opt_bool(raw, "imdsv2_required", where),
        tags=_opt_str_dict(raw, "tags", where),
    )


def _parse_external(raw: Any, where: str) -> ExternalPrincipal:
    if not isinstance(raw, Mapping):
        raise InputError(f"{where}: must be an object")
    arn = _req_str(raw, "arn", where)
    if arn != "*" and parse_arn(arn) is None and not is_account_id(arn):
        raise InputError(f"{where}: {arn!r} is not an ARN, account id or '*'")
    return ExternalPrincipal(
        arn=arn,
        account_id=account_of(arn),
        description=_opt_str(raw, "description", where),
        known=_opt_bool(raw, "known", where) or False,
    )


# ---------------------------------------------------------------------------
# field helpers
# ---------------------------------------------------------------------------


def _principal_arn(
    raw: Mapping[str, Any], where: str, account_id: str, kind: str, name: str, path: str
) -> str:
    arn = _opt_str(raw, "arn", where)
    if arn is None:
        normalized_path = path if path.endswith("/") else path + "/"
        return f"arn:aws:iam::{account_id}:{kind}{normalized_path}{name}"
    parsed = parse_arn(arn)
    if parsed is None or parsed.service != "iam" or parsed.resource_type != kind:
        raise InputError(f"{where}: {arn!r} is not an IAM {kind} ARN")
    return arn


def _parse_inline_policies(
    raw: Mapping[str, Any], where: str, prefix: str, warnings: list[str]
) -> dict[str, PolicyDocument]:
    value = raw.get("inline_policies")
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise InputError(
            f"{where}.inline_policies: must be an object mapping policy names to documents"
        )
    out: dict[str, PolicyDocument] = {}
    for name, doc in value.items():
        if not isinstance(name, str) or not name:
            raise InputError(f"{where}.inline_policies: policy names must be non-empty strings")
        out[name] = parse_policy_document(doc, f"{prefix}:{name}", warnings=warnings)
    return out


def _req_str(raw: Mapping[str, Any], key: str, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise InputError(f"{where}: {key} is required and must be a non-empty string")
    return value


def _opt_str(raw: Mapping[str, Any], key: str, where: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise InputError(f"{where}: {key} must be a string")
    return value


def _opt_bool(raw: Mapping[str, Any], key: str, where: str) -> bool | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InputError(f"{where}: {key} must be true or false")
    return value


def _opt_int(raw: Mapping[str, Any], key: str, where: str) -> int | None:
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError(f"{where}: {key} must be an integer")
    return int(value)


def _opt_list(raw: Mapping[str, Any], key: str, where: str) -> list[Any]:
    value = raw.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise InputError(f"{where}: {key} must be a list")
    return value


def _opt_str_list(raw: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    items = _opt_list(raw, key, where)
    for item in items:
        if not isinstance(item, str):
            raise InputError(f"{where}: {key} entries must be strings")
    return tuple(items)


def _opt_str_dict(raw: Mapping[str, Any], key: str, where: str) -> dict[str, str]:
    value = raw.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise InputError(f"{where}: {key} must be an object of string pairs")
    out: dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise InputError(f"{where}: {key} must be an object of string pairs")
        out[k] = v
    return out


def _reject_duplicates(values: list[str], section: str, source: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise InputError(f"{source}: duplicate entry {value!r} in {section}")
        seen.add(value)
