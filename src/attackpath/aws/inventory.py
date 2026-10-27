"""Read-only AWS inventory collector.

:class:`AwsInventoryCollector` turns a boto3 session into an environment snapshot
document in the exact schema :func:`attackpath.parser.environment_parser.parse_environment`
accepts, so a scanned account is analyzed by the same offline engine as a fixture.

Design points:

* every API call goes through one retry/classification helper, so throttling,
  access denied and other per-resource failures are handled uniformly and end up
  in the snapshot's ``coverage`` section instead of aborting the scan;
* a failure of a service's primary listing marks the service ``missing``;
* only the read-only operations in :mod:`attackpath.aws.safeguards` are used and
  the safeguards are installed on the session as a second line of defence;
* the collector validates its own output with the strict parser before returning.

boto3/botocore are imported lazily so that importing this module never requires
the optional ``aws`` extra.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import sleep
from typing import Any
from urllib.parse import unquote

from attackpath import __version__
from attackpath.aws.safeguards import install_safeguards
from attackpath.exceptions import AwsScanError, InputError
from attackpath.models.environment import CoverageStatus
from attackpath.parser.environment_parser import parse_environment

log = logging.getLogger(__name__)

SUPPORTED_SERVICES: tuple[str, ...] = ("iam", "s3", "lambda", "ec2")
SCHEMA_VERSION = "1.0"
GENERATOR = "attackpath aws-scan"

THROTTLING_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "RequestThrottled",
        "SlowDown",
    }
)
ACCESS_DENIED_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"}
)

_BACKOFF_BASE_SECONDS = 0.5
_BACKOFF_CAP_SECONDS = 20.0
_PUBLIC_ACL_GROUPS = frozenset({"AllUsers", "AuthenticatedUsers"})
_ACL_READ_PERMISSIONS = frozenset({"READ", "FULL_CONTROL"})
_ACL_WRITE_PERMISSIONS = frozenset({"WRITE", "WRITE_ACP", "FULL_CONTROL"})
_SENSITIVITY_TAG_KEYS = ("dataclassification", "sensitivity")
_SENSITIVITY_VALUES = frozenset({"high", "medium", "low"})
_AUTHORIZATION_DETAIL_KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
_NOTE_EXAMPLES = 3


@dataclass(frozen=True)
class _Paging:
    """Token names of a manually paginated list operation."""

    input_token: str
    output_token: str
    truncated_key: str | None = None


_IAM_PAGING = _Paging("Marker", "Marker", "IsTruncated")
_S3_PAGING = _Paging("ContinuationToken", "ContinuationToken")
_LAMBDA_PAGING = _Paging("Marker", "NextMarker")
_EC2_PAGING = _Paging("NextToken", "NextToken")
_PUBLIC_IPV4 = "0.0.0.0/0"
_PUBLIC_IPV6 = "::/0"


@dataclass(frozen=True)
class _CallResult:
    """Outcome of one API call after retries."""

    value: Any = None
    error_code: str | None = None
    message: str = ""
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.error_code is None

    @property
    def throttled(self) -> bool:
        return self.error_code in THROTTLING_CODES


@dataclass
class _ServiceCoverage:
    """Coverage bookkeeping for one service while it is being inventoried."""

    status: CoverageStatus = CoverageStatus.COMPLETE
    notes: list[str] = field(default_factory=list)
    failures: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)

    def degrade(self, status: CoverageStatus) -> None:
        order = (CoverageStatus.COMPLETE, CoverageStatus.PARTIAL, CoverageStatus.MISSING)
        if order.index(status) > order.index(self.status):
            self.status = status

    def note(self, text: str, status: CoverageStatus = CoverageStatus.PARTIAL) -> None:
        self.notes.append(text)
        self.degrade(status)

    def failure(self, code: str, label: str, detail: str, resource: str) -> None:
        self.failures.setdefault((code, label, detail), []).append(resource)
        self.degrade(CoverageStatus.PARTIAL)

    def document(self) -> dict[str, Any]:
        notes = list(self.notes)
        for (code, label, detail), resources in self.failures.items():
            suffix = f" ({detail})" if detail else ""
            if len(resources) == 1:
                notes.append(f"{code} on {label} for {resources[0]}{suffix}")
            else:
                examples = ", ".join(resources[:_NOTE_EXAMPLES])
                more = ", ..." if len(resources) > _NOTE_EXAMPLES else ""
                notes.append(
                    f"{code} on {label} for {len(resources)} resources ({examples}{more}){suffix}"
                )
        return {"status": self.status.value, "notes": notes}


class AwsInventoryCollector:
    """Collect a read-only snapshot of IAM, S3, Lambda and EC2 from one AWS account.

    ``session`` is a ``boto3.session.Session`` (or any object exposing the same
    ``client()`` and ``events`` members). ``sleeper`` and ``max_attempts`` control
    the throttling back-off and are injectable for tests.
    """

    def __init__(
        self,
        session: Any,
        region: str,
        services: Sequence[str] = SUPPORTED_SERVICES,
        sleeper: Callable[[float], object] = sleep,
        max_attempts: int = 6,
    ) -> None:
        if not region:
            raise AwsScanError("a region is required")
        if max_attempts < 1:
            raise AwsScanError("max_attempts must be at least 1")
        self._session = session
        self._region = region
        self._services = normalize_services(services)
        self._sleep = sleeper
        self._max_attempts = max_attempts
        self._clients: dict[tuple[str, str], Any] = {}
        self._coverage: dict[str, _ServiceCoverage] = {}
        self._instance_profile_roles: dict[str, str] = {}
        install_safeguards(session)

    @property
    def services(self) -> tuple[str, ...]:
        return self._services

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def collect(self) -> dict[str, Any]:
        """Inventory the account and return a validated snapshot document."""
        self._coverage = {}
        self._instance_profile_roles = {}
        account_id, caller_arn = self._caller_identity()
        log.info("inventorying account %s as %s", account_id, caller_arn)

        snapshot: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "metadata": {
                "name": f"aws-account-{account_id}",
                "description": (
                    f"Read-only inventory of AWS account {account_id} collected by "
                    f"{GENERATOR} (services: {', '.join(self._services)}; region {self._region})"
                ),
                "synthetic": False,
                "source": "aws-scan",
                "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "generator": GENERATOR,
                "regions": [self._region],
            },
            "account_id": account_id,
            "coverage": {},
            "users": [],
            "groups": [],
            "roles": [],
            "managed_policies": [],
            "s3_buckets": [],
            "lambda_functions": [],
            "security_groups": [],
            "ec2_instances": [],
        }
        if "iam" in self._services:
            snapshot.update(self._collect_iam())
        if "s3" in self._services:
            snapshot["s3_buckets"] = self._collect_s3(account_id)
        if "lambda" in self._services:
            snapshot["lambda_functions"] = self._collect_lambda(account_id)
        if "ec2" in self._services:
            groups, instances = self._collect_ec2(account_id)
            snapshot["security_groups"] = groups
            snapshot["ec2_instances"] = instances
        snapshot["coverage"] = self._coverage_document()

        try:
            parse_environment(snapshot, "aws-scan")
        except InputError as exc:
            raise AwsScanError(f"collected snapshot failed validation: {exc}") from exc
        return snapshot

    # ------------------------------------------------------------------
    # STS
    # ------------------------------------------------------------------

    def _caller_identity(self) -> tuple[str, str]:
        sts = self._client("sts")
        result = self._call(sts, "get_caller_identity")
        if not result.ok:
            raise AwsScanError(
                f"sts:GetCallerIdentity failed ({result.error_code}): {result.message}"
            )
        account_id = str(result.value.get("Account", ""))
        caller_arn = str(result.value.get("Arn", ""))
        if not account_id:
            raise AwsScanError("sts:GetCallerIdentity returned no account id")
        if caller_arn.endswith(":root"):
            raise AwsScanError("refusing to scan with root credentials; use an IAM identity")
        return account_id, caller_arn

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------

    def _collect_iam(self) -> dict[str, list[dict[str, Any]]]:
        empty: dict[str, list[dict[str, Any]]] = {
            "users": [],
            "groups": [],
            "roles": [],
            "managed_policies": [],
        }
        iam = self._client("iam")
        pages, failure = self._paginate(iam, "get_account_authorization_details", _IAM_PAGING)
        if failure is not None:
            self._mark_missing("iam", iam, "get_account_authorization_details", failure)
            return empty

        details: dict[str, list[dict[str, Any]]] = {key: [] for key in _AUTHORIZATION_DETAIL_KEYS}
        for page in pages:
            for key in _AUTHORIZATION_DETAIL_KEYS:
                details[key].extend(page.get(key) or [])
        # Instance profiles are listed with their role; EC2 instances only name the profile.
        for item in details["RoleDetailList"]:
            role_arn = item.get("Arn")
            for profile in item.get("InstanceProfileList") or []:
                if role_arn and profile.get("Arn"):
                    self._instance_profile_roles[str(profile["Arn"])] = str(role_arn)

        managed = [
            policy
            for item in details["Policies"]
            if (policy := self._managed_policy(iam, item)) is not None
        ]
        users = [self._user(iam, item) for item in details["UserDetailList"]]
        groups = [self._group(item) for item in details["GroupDetailList"]]
        roles = [
            role for item in details["RoleDetailList"] if (role := self._role(item)) is not None
        ]
        managed.extend(self._unresolved_policies(iam, managed, users, groups, roles))
        return {"users": users, "groups": groups, "roles": roles, "managed_policies": managed}

    def _user(self, iam: Any, item: Mapping[str, Any]) -> dict[str, Any]:
        name = str(item["UserName"])
        resource = f"user {name}"
        user: dict[str, Any] = {
            "name": name,
            "arn": item.get("Arn"),
            "path": item.get("Path") or "/",
            "groups": list(item.get("GroupList") or []),
            "inline_policies": self._inline_policies(item.get("UserPolicyList"), resource),
            "attached_policies": _attached_arns(item),
            "permissions_boundary": _boundary_arn(item),
            "tags": _tags_from_list(item.get("Tags")),
        }

        key_pages, failure = self._paginate(iam, "list_access_keys", _IAM_PAGING, UserName=name)
        if failure is None:
            user["access_keys"] = [
                {
                    "key_id": key["AccessKeyId"],
                    "status": key.get("Status") or "Active",
                    "created": _iso(key.get("CreateDate")),
                }
                for page in key_pages
                for key in page.get("AccessKeyMetadata") or []
            ]
        else:
            self._record_failure("iam", iam, "list_access_keys", failure, resource)
            user["access_keys"] = []

        mfa_pages, failure = self._paginate(iam, "list_mfa_devices", _IAM_PAGING, UserName=name)
        if failure is None:
            user["mfa_enabled"] = any(page.get("MFADevices") for page in mfa_pages)
        else:
            self._record_failure("iam", iam, "list_mfa_devices", failure, resource)
            user["mfa_enabled"] = None

        profile, code = self._fetch(
            "iam",
            iam,
            "get_login_profile",
            resource=resource,
            tolerated=("NoSuchEntity",),
            UserName=name,
        )
        if profile is not None:
            user["console_access"] = True
        elif code == "NoSuchEntity":
            user["console_access"] = False
        else:
            user["console_access"] = None
        return user

    def _group(self, item: Mapping[str, Any]) -> dict[str, Any]:
        name = str(item["GroupName"])
        return {
            "name": name,
            "arn": item.get("Arn"),
            "path": item.get("Path") or "/",
            "inline_policies": self._inline_policies(item.get("GroupPolicyList"), f"group {name}"),
            "attached_policies": _attached_arns(item),
        }

    def _role(self, item: Mapping[str, Any]) -> dict[str, Any] | None:
        name = str(item["RoleName"])
        resource = f"role {name}"
        trust = _decode_policy(item.get("AssumeRolePolicyDocument"))
        if trust is None:
            self._coverage["iam"].note(
                f"{resource} skipped: its trust policy could not be decoded",
            )
            return None
        last_used = item.get("RoleLastUsed") or {}
        return {
            "name": name,
            "arn": item.get("Arn"),
            "path": item.get("Path") or "/",
            "trust_policy": trust,
            "inline_policies": self._inline_policies(item.get("RolePolicyList"), resource),
            "attached_policies": _attached_arns(item),
            "permissions_boundary": _boundary_arn(item),
            "description": item.get("Description"),
            "last_used": _iso(last_used.get("LastUsedDate")),
            "tags": _tags_from_list(item.get("Tags")),
        }

    def _inline_policies(self, raw: Any, resource: str) -> dict[str, Any]:
        policies: dict[str, Any] = {}
        for entry in raw or []:
            policy_name = str(entry.get("PolicyName", ""))
            document = _decode_policy(entry.get("PolicyDocument"))
            if not policy_name or document is None:
                self._coverage["iam"].note(
                    f"inline policy {policy_name or '<unnamed>'} of {resource} skipped: "
                    "document could not be decoded"
                )
                continue
            policies[policy_name] = document
        return policies

    def _managed_policy(self, iam: Any, item: Mapping[str, Any]) -> dict[str, Any] | None:
        arn = str(item.get("Arn", ""))
        default_version = item.get("DefaultVersionId")
        document: dict[str, Any] | None = None
        for version in item.get("PolicyVersionList") or []:
            if version.get("IsDefaultVersion") or (
                default_version is not None and version.get("VersionId") == default_version
            ):
                document = _decode_policy(version.get("Document"))
                break
        if document is None and default_version:
            document = self._policy_version_document(iam, arn, str(default_version))
        if document is None:
            self._coverage["iam"].note(
                f"managed policy {arn} skipped: default version document unavailable"
            )
            return None
        return _managed_policy_entry(
            arn=arn,
            name=item.get("PolicyName"),
            document=document,
            attachment_count=item.get("AttachmentCount"),
            default_version_id=default_version,
        )

    def _policy_version_document(
        self, iam: Any, arn: str, version_id: str
    ) -> dict[str, Any] | None:
        response, _ = self._fetch(
            "iam",
            iam,
            "get_policy_version",
            resource=f"policy {arn}",
            PolicyArn=arn,
            VersionId=version_id,
        )
        if response is None:
            return None
        return _decode_policy((response.get("PolicyVersion") or {}).get("Document"))

    def _unresolved_policies(
        self,
        iam: Any,
        managed: list[dict[str, Any]],
        *principal_lists: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Fetch attached managed policies that the account details did not include."""
        known = {policy["arn"] for policy in managed}
        referenced: set[str] = set()
        for principals in principal_lists:
            for principal in principals:
                referenced.update(principal.get("attached_policies") or [])
                boundary = principal.get("permissions_boundary")
                if boundary:
                    referenced.add(boundary)
        resolved: list[dict[str, Any]] = []
        for arn in sorted(referenced - known):
            response, _ = self._fetch(
                "iam", iam, "get_policy", resource=f"policy {arn}", PolicyArn=arn
            )
            if response is None:
                continue
            meta = response.get("Policy") or {}
            version_id = meta.get("DefaultVersionId")
            if not version_id:
                self._coverage["iam"].note(f"managed policy {arn} has no default version")
                continue
            document = self._policy_version_document(iam, arn, str(version_id))
            if document is None:
                continue
            resolved.append(
                _managed_policy_entry(
                    arn=arn,
                    name=meta.get("PolicyName"),
                    document=document,
                    attachment_count=meta.get("AttachmentCount"),
                    default_version_id=version_id,
                )
            )
        return resolved

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------

    def _collect_s3(self, account_id: str) -> list[dict[str, Any]]:
        s3 = self._client("s3")
        pages, failure = self._paginate(s3, "list_buckets", _S3_PAGING)
        if failure is not None:
            self._mark_missing("s3", s3, "list_buckets", failure)
            return []
        return [
            self._bucket(account_id, item)
            for page in pages
            for item in page.get("Buckets") or []
            if item.get("Name")
        ]

    def _bucket(self, account_id: str, item: Mapping[str, Any]) -> dict[str, Any]:
        name = str(item["Name"])
        resource = f"bucket {name}"
        hint = item.get("BucketRegion")
        client = self._client("s3", str(hint) if hint else None)

        location, _ = self._fetch(
            "s3", client, "get_bucket_location", resource=resource, Bucket=name
        )
        region = _bucket_region(location) if location is not None else (str(hint) if hint else None)
        client = self._client("s3", region)

        bucket: dict[str, Any] = {
            "name": name,
            "arn": item.get("BucketArn") or f"arn:aws:s3:::{name}",
            "account_id": account_id,
            "region": region,
        }

        policy_response, _ = self._fetch(
            "s3",
            client,
            "get_bucket_policy",
            resource=resource,
            tolerated=("NoSuchBucketPolicy",),
            Bucket=name,
        )
        bucket["bucket_policy"] = None
        if policy_response is not None:
            document = _decode_policy(policy_response.get("Policy"))
            if document is None:
                self._coverage["s3"].note(f"{resource}: bucket policy could not be decoded")
            bucket["bucket_policy"] = document

        pab_response, _ = self._fetch(
            "s3",
            client,
            "get_public_access_block",
            resource=resource,
            tolerated=("NoSuchPublicAccessBlockConfiguration",),
            Bucket=name,
        )
        bucket["public_access_block"] = None
        if pab_response is not None:
            config = pab_response.get("PublicAccessBlockConfiguration") or {}
            bucket["public_access_block"] = {
                "block_public_acls": bool(config.get("BlockPublicAcls", False)),
                "ignore_public_acls": bool(config.get("IgnorePublicAcls", False)),
                "block_public_policy": bool(config.get("BlockPublicPolicy", False)),
                "restrict_public_buckets": bool(config.get("RestrictPublicBuckets", False)),
            }

        acl_response, _ = self._fetch(
            "s3", client, "get_bucket_acl", resource=resource, Bucket=name
        )
        bucket["acl_public_read"] = None
        bucket["acl_public_write"] = None
        if acl_response is not None:
            grants = acl_response.get("Grants") or []
            bucket["acl_public_read"] = _has_public_grant(grants, _ACL_READ_PERMISSIONS)
            bucket["acl_public_write"] = _has_public_grant(grants, _ACL_WRITE_PERMISSIONS)

        encryption_response, _ = self._fetch(
            "s3",
            client,
            "get_bucket_encryption",
            resource=resource,
            tolerated=("ServerSideEncryptionConfigurationNotFoundError",),
            Bucket=name,
        )
        bucket["encryption"] = (
            _encryption_algorithm(encryption_response) if encryption_response is not None else None
        )

        tagging_response, _ = self._fetch(
            "s3",
            client,
            "get_bucket_tagging",
            resource=resource,
            tolerated=("NoSuchTagSet",),
            Bucket=name,
        )
        tags = _tags_from_list(tagging_response.get("TagSet")) if tagging_response else {}
        bucket["tags"] = tags
        sensitivity = _sensitivity_from_tags(tags)
        if sensitivity is not None:
            bucket["sensitivity"] = sensitivity
        return bucket

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------

    def _collect_lambda(self, account_id: str) -> list[dict[str, Any]]:
        lam = self._client("lambda")
        pages, failure = self._paginate(lam, "list_functions", _LAMBDA_PAGING)
        if failure is not None:
            self._mark_missing("lambda", lam, "list_functions", failure)
            return []
        return [
            self._function(lam, account_id, item)
            for page in pages
            for item in page.get("Functions") or []
            if item.get("FunctionName")
        ]

    def _function(self, lam: Any, account_id: str, item: Mapping[str, Any]) -> dict[str, Any]:
        name = str(item["FunctionName"])
        resource = f"function {name}"
        arn = str(
            item.get("FunctionArn") or f"arn:aws:lambda:{self._region}:{account_id}:function:{name}"
        )
        function: dict[str, Any] = {
            "name": name,
            "arn": arn,
            "region": self._region,
            "runtime": item.get("Runtime"),
            "role_arn": item.get("Role"),
            "description": item.get("Description") or None,
        }

        policy_response, _ = self._fetch(
            "lambda",
            lam,
            "get_policy",
            resource=resource,
            tolerated=("ResourceNotFoundException",),
            FunctionName=name,
        )
        function["resource_policy"] = None
        if policy_response is not None:
            document = _decode_policy(policy_response.get("Policy"))
            if document is None:
                self._coverage["lambda"].note(f"{resource}: resource policy could not be decoded")
            function["resource_policy"] = document

        tags_response, _ = self._fetch("lambda", lam, "list_tags", resource=resource, Resource=arn)
        tags = tags_response.get("Tags") if tags_response else None
        function["tags"] = {str(k): str(v) for k, v in (tags or {}).items()}
        return function

    # ------------------------------------------------------------------
    # EC2 (instances, security groups and the routing needed for exposure)
    # ------------------------------------------------------------------

    def _collect_ec2(self, account_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        ec2 = self._client("ec2")
        pages, failure = self._paginate(ec2, "describe_instances", _EC2_PAGING)
        if failure is not None:
            self._mark_missing("ec2", ec2, "describe_instances", failure)
            return [], []
        group_pages, failure = self._paginate(ec2, "describe_security_groups", _EC2_PAGING)
        if failure is not None:
            self._coverage_for("ec2").note(
                f"{_label(ec2, 'describe_security_groups')} failed ({failure.error_code}): "
                "the network exposure of instances cannot be determined"
            )
        groups = [
            self._security_group(item)
            for page in group_pages
            for item in page.get("SecurityGroups") or []
            if item.get("GroupId")
        ]
        route_tables = self._route_tables(ec2)
        instances = [
            self._instance(account_id, item, route_tables)
            for page in pages
            for reservation in page.get("Reservations") or []
            for item in reservation.get("Instances") or []
            if item.get("InstanceId")
        ]
        return groups, instances

    def _route_tables(self, ec2: Any) -> list[dict[str, Any]] | None:
        pages, failure = self._paginate(ec2, "describe_route_tables", _EC2_PAGING)
        if failure is not None:
            self._coverage_for("ec2").note(
                f"{_label(ec2, 'describe_route_tables')} failed ({failure.error_code}): whether "
                "instance subnets route to an internet gateway is unknown"
            )
            return None
        return [table for page in pages for table in page.get("RouteTables") or []]

    def _security_group(self, item: Mapping[str, Any]) -> dict[str, Any]:
        rules: list[dict[str, Any]] = []
        for permission in item.get("IpPermissions") or []:
            protocol = str(permission.get("IpProtocol", "-1")).lower()
            rule: dict[str, Any] = {
                "protocol": "all" if protocol == "-1" else protocol,
                "cidrs": [
                    str(r["CidrIp"]) for r in permission.get("IpRanges") or [] if r.get("CidrIp")
                ],
                "ipv6_cidrs": [
                    str(r["CidrIpv6"])
                    for r in permission.get("Ipv6Ranges") or []
                    if r.get("CidrIpv6")
                ],
                "source_groups": [
                    str(g["GroupId"])
                    for g in permission.get("UserIdGroupPairs") or []
                    if g.get("GroupId")
                ]
                + [
                    str(p["PrefixListId"])
                    for p in permission.get("PrefixListIds") or []
                    if p.get("PrefixListId")
                ],
            }
            if not (rule["cidrs"] or rule["ipv6_cidrs"] or rule["source_groups"]):
                continue
            from_port, to_port = permission.get("FromPort"), permission.get("ToPort")
            if (
                rule["protocol"] in ("tcp", "udp")
                and isinstance(from_port, int)
                and isinstance(to_port, int)
                and from_port >= 0
                and to_port >= 0
            ):
                rule["from_port"], rule["to_port"] = from_port, to_port
            descriptions = [
                str(r["Description"])
                for r in permission.get("IpRanges") or []
                if r.get("Description")
            ]
            if descriptions:
                rule["description"] = descriptions[0]
            rules.append(rule)
        return {
            "group_id": str(item["GroupId"]),
            "name": item.get("GroupName"),
            "vpc_id": item.get("VpcId"),
            "description": item.get("Description") or None,
            "ingress": rules,
            "tags": _tags_from_list(item.get("Tags")),
        }

    def _instance(
        self, account_id: str, item: Mapping[str, Any], route_tables: list[dict[str, Any]] | None
    ) -> dict[str, Any]:
        instance_id = str(item["InstanceId"])
        tags = _tags_from_list(item.get("Tags"))
        profile = (item.get("IamInstanceProfile") or {}).get("Arn")
        role_arn = self._instance_profile_roles.get(str(profile)) if profile else None
        if profile and role_arn is None:
            self._coverage_for("ec2").note(
                f"instance {instance_id}: the role behind instance profile {profile} is not "
                "known (IAM inventory missing or the profile is not listed with its role)"
            )
        metadata = item.get("MetadataOptions") or {}
        tokens = metadata.get("HttpTokens")
        imdsv2: bool | None
        if metadata.get("HttpEndpoint") == "disabled":
            imdsv2 = True  # no metadata service at all: nothing to steal through IMDSv1
        elif tokens is None:
            imdsv2 = None
        else:
            imdsv2 = str(tokens) == "required"
        subnet_id = item.get("SubnetId")
        vpc_id = item.get("VpcId")
        internet_facing = (
            _subnet_routes_to_internet_gateway(route_tables, subnet_id, vpc_id)
            if route_tables is not None
            else None
        )
        return {
            "instance_id": instance_id,
            "arn": f"arn:aws:ec2:{self._region}:{account_id}:instance/{instance_id}",
            "region": self._region,
            "name": tags.get("Name"),
            "state": str((item.get("State") or {}).get("Name") or "unknown"),
            "public_ip": item.get("PublicIpAddress"),
            "public_dns": item.get("PublicDnsName") or None,
            "subnet_id": subnet_id,
            "vpc_id": vpc_id,
            "internet_facing": internet_facing,
            "security_groups": [
                str(g["GroupId"]) for g in item.get("SecurityGroups") or [] if g.get("GroupId")
            ],
            "role_arn": role_arn,
            "instance_profile_arn": str(profile) if profile else None,
            "imdsv2_required": imdsv2,
            "tags": tags,
        }

    # ------------------------------------------------------------------
    # call plumbing
    # ------------------------------------------------------------------

    def _client(self, service: str, region: str | None = None) -> Any:
        key = (service, region or self._region)
        client = self._clients.get(key)
        if client is None:
            from botocore.config import Config

            config = Config(
                retries={"max_attempts": 3, "mode": "standard"},
                user_agent_extra=f"attackpath-aws-scan/{__version__}",
            )
            client = self._session.client(service, region_name=key[1], config=config)
            self._clients[key] = client
        return client

    def _call(self, client: Any, method: str, **params: Any) -> _CallResult:
        """Invoke ``client.method(**params)``, retrying throttling with back-off."""
        from botocore.exceptions import ClientError

        operation = getattr(client, method)
        delay = _BACKOFF_BASE_SECONDS
        attempt = 0
        while True:
            attempt += 1
            try:
                return _CallResult(value=operation(**params), attempts=attempt)
            except ClientError as exc:
                error = exc.response.get("Error") or {}
                code = str(error.get("Code") or "ClientError")
                message = str(error.get("Message") or exc)
                if code not in THROTTLING_CODES or attempt >= self._max_attempts:
                    return _CallResult(error_code=code, message=message, attempts=attempt)
                log.debug(
                    "%s throttled (%s); retrying in %.1fs (attempt %d of %d)",
                    _label(client, method),
                    code,
                    delay,
                    attempt,
                    self._max_attempts,
                )
                self._sleep(delay)
                delay = min(delay * 2, _BACKOFF_CAP_SECONDS)

    def _paginate(
        self, client: Any, method: str, paging: _Paging, **params: Any
    ) -> tuple[list[dict[str, Any]], _CallResult | None]:
        """Collect all pages of a list call; return them with the failure that stopped it."""
        pages: list[dict[str, Any]] = []
        request = dict(params)
        seen_tokens: set[str] = set()
        while True:
            result = self._call(client, method, **request)
            if not result.ok:
                return pages, result
            page: dict[str, Any] = result.value or {}
            pages.append(page)
            token = page.get(paging.output_token)
            if paging.truncated_key is not None and not page.get(paging.truncated_key):
                return pages, None
            if not token or token in seen_tokens:
                return pages, None
            seen_tokens.add(str(token))
            request[paging.input_token] = token

    def _fetch(
        self,
        service: str,
        client: Any,
        method: str,
        *,
        resource: str,
        tolerated: Iterable[str] = (),
        **params: Any,
    ) -> tuple[Any | None, str | None]:
        """Per-resource call: ``(response, None)`` or ``(None, error_code)``.

        Error codes in ``tolerated`` mean "the attribute does not exist" and are
        not coverage gaps; any other failure is recorded against the service.
        """
        result = self._call(client, method, **params)
        if result.ok:
            return result.value, None
        if result.error_code not in set(tolerated):
            self._record_failure(service, client, method, result, resource)
        return None, result.error_code

    def _record_failure(
        self, service: str, client: Any, method: str, result: _CallResult, resource: str
    ) -> None:
        detail = f"gave up after {result.attempts} attempts" if result.throttled else ""
        code = result.error_code or "ClientError"
        label = _label(client, method)
        if code in ACCESS_DENIED_CODES:
            log.warning("%s on %s for %s", code, label, resource)
        else:
            log.debug("%s on %s for %s: %s", code, label, resource, result.message)
        self._coverage_for(service).failure(code, label, detail, resource)

    def _mark_missing(self, service: str, client: Any, method: str, result: _CallResult) -> None:
        label = _label(client, method)
        if result.throttled:
            text = f"{label} failed after {result.attempts} attempts ({result.error_code})"
        else:
            text = f"{label} failed ({result.error_code}): {result.message}"
        log.warning("%s inventory missing: %s", service, text)
        self._coverage_for(service).note(text, CoverageStatus.MISSING)

    def _coverage_for(self, service: str) -> _ServiceCoverage:
        return self._coverage.setdefault(service, _ServiceCoverage())

    def _coverage_document(self) -> dict[str, Any]:
        services: dict[str, Any] = {}
        for service in SUPPORTED_SERVICES:
            if service in self._services:
                services[service] = self._coverage_for(service).document()
            else:
                services[service] = {
                    "status": CoverageStatus.MISSING.value,
                    "notes": ["service was not requested (see --services)"],
                }
        notes: list[str] = []
        if "lambda" in self._services:
            notes.append(f"Lambda functions were inventoried in region {self._region} only")
        if "ec2" in self._services:
            notes.append(
                f"EC2 instances and security groups were inventoried in region {self._region} only"
            )
        return {"services": services, "notes": notes}


# ----------------------------------------------------------------------
# module helpers
# ----------------------------------------------------------------------


def normalize_services(services: Sequence[str]) -> tuple[str, ...]:
    """Validate and de-duplicate a service selection, preserving the canonical order."""
    requested = [s.strip().lower() for s in services if s and s.strip()]
    unknown = sorted({s for s in requested if s not in SUPPORTED_SERVICES})
    if unknown:
        raise AwsScanError(
            f"unsupported service(s): {', '.join(unknown)} "
            f"(supported: {', '.join(SUPPORTED_SERVICES)})"
        )
    if not requested:
        raise AwsScanError("at least one service must be selected")
    return tuple(s for s in SUPPORTED_SERVICES if s in requested)


def _decode_policy(value: Any) -> dict[str, Any] | None:
    """Return a policy document as a dict from a dict, JSON string or URL-encoded JSON string."""
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str) or not value:
        return None
    for candidate in (value, unquote(value)):
        try:
            decoded = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(decoded, Mapping):
            return dict(decoded)
        return None
    return None


def _label(client: Any, method: str) -> str:
    """Human-readable ``service:Operation`` label for notes, derived from the client model."""
    try:
        service = str(client.meta.service_model.service_id.hyphenize())
        operation = str(client.meta.method_to_api_mapping.get(method, method))
    except AttributeError:
        return method
    return f"{service}:{operation}"


def _managed_policy_entry(
    *,
    arn: str,
    name: Any,
    document: dict[str, Any],
    attachment_count: Any,
    default_version_id: Any,
) -> dict[str, Any]:
    parts = arn.split(":")
    return {
        "arn": arn,
        "name": str(name) if name else arn.rsplit("/", 1)[-1],
        "document": document,
        "is_aws_managed": len(parts) > 4 and parts[4] == "aws",
        "attachment_count": attachment_count if isinstance(attachment_count, int) else None,
        "default_version_id": str(default_version_id) if default_version_id else None,
    }


def _attached_arns(item: Mapping[str, Any]) -> list[str]:
    return [
        str(entry["PolicyArn"])
        for entry in item.get("AttachedManagedPolicies") or []
        if entry.get("PolicyArn")
    ]


def _boundary_arn(item: Mapping[str, Any]) -> str | None:
    boundary = item.get("PermissionsBoundary") or {}
    arn = boundary.get("PermissionsBoundaryArn")
    return str(arn) if arn else None


def _tags_from_list(raw: Any) -> dict[str, str]:
    tags: dict[str, str] = {}
    for entry in raw or []:
        key = entry.get("Key")
        if key is not None:
            tags[str(key)] = str(entry.get("Value", ""))
    return tags


def _sensitivity_from_tags(tags: Mapping[str, str]) -> str | None:
    lowered = {key.lower(): value.strip().lower() for key, value in tags.items()}
    for wanted in _SENSITIVITY_TAG_KEYS:
        value = lowered.get(wanted)
        if value in _SENSITIVITY_VALUES:
            return value
    return None


def _bucket_region(location: Mapping[str, Any]) -> str:
    constraint = location.get("LocationConstraint")
    if not constraint:
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    return str(constraint)


def _subnet_routes_to_internet_gateway(
    tables: list[dict[str, Any]], subnet_id: Any, vpc_id: Any
) -> bool | None:
    """Whether the route table of ``subnet_id`` (or the VPC's main table) has an IGW default route."""
    explicit: dict[str, Any] | None = None
    main: dict[str, Any] | None = None
    for candidate in tables:
        for association in candidate.get("Associations") or []:
            if subnet_id and association.get("SubnetId") == subnet_id:
                explicit = candidate
            if association.get("Main") and vpc_id and candidate.get("VpcId") == vpc_id:
                main = candidate
    table = explicit or main
    if table is None:
        return None
    for route in table.get("Routes") or []:
        gateway = str(route.get("GatewayId") or "")
        if not gateway.startswith("igw-") or route.get("State", "active") != "active":
            continue
        if route.get("DestinationCidrBlock") == _PUBLIC_IPV4:
            return True
        if route.get("DestinationIpv6CidrBlock") == _PUBLIC_IPV6:
            return True
    return False


def _has_public_grant(grants: Iterable[Mapping[str, Any]], permissions: frozenset[str]) -> bool:
    for grant in grants:
        grantee = grant.get("Grantee") or {}
        uri = str(grantee.get("URI") or "")
        group = uri.rstrip("/").rsplit("/", 1)[-1]
        if group in _PUBLIC_ACL_GROUPS and grant.get("Permission") in permissions:
            return True
    return False


def _encryption_algorithm(response: Mapping[str, Any]) -> str | None:
    configuration = response.get("ServerSideEncryptionConfiguration") or {}
    for rule in configuration.get("Rules") or []:
        default = rule.get("ApplyServerSideEncryptionByDefault") or {}
        algorithm = default.get("SSEAlgorithm")
        if algorithm:
            return str(algorithm)
    return None


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        moment: datetime = value.astimezone(UTC) if value.tzinfo is not None else value
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


__all__ = [
    "ACCESS_DENIED_CODES",
    "SUPPORTED_SERVICES",
    "THROTTLING_CODES",
    "AwsInventoryCollector",
    "normalize_services",
]
