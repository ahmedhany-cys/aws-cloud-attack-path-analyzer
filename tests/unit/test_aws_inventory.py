"""Tests for the read-only inventory collector using botocore stubs.

Every client is created from a boto3 session with fake static credentials and is
backed by ``botocore.stub.Stubber``; no credentials file and no network are used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import pytest

from attackpath.aws.inventory import AwsInventoryCollector, _decode_policy
from attackpath.exceptions import AwsScanError
from attackpath.parser.environment_parser import parse_environment

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

pytestmark = pytest.mark.aws

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCANNER_ARN = f"arn:aws:iam::{ACCOUNT}:user/scanner"
ALLOW_S3_READ = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}
LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
PUBLIC_READ_BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::legacy-backups/*",
        }
    ],
}
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
NO_PAB = "NoSuchPublicAccessBlockConfiguration"
NO_SSE = "ServerSideEncryptionConfigurationNotFoundError"


def encoded(document: dict[str, Any]) -> str:
    """IAM returns policy documents URL-encoded; botocore decodes them on the way in."""
    return quote(json.dumps(document))


# ---------------------------------------------------------------------------
# stubbed session plumbing
# ---------------------------------------------------------------------------


@dataclass
class Clients:
    session: Any
    stubs: dict[str, Stubber]
    sleeps: list[float] = field(default_factory=list)

    def __getitem__(self, service: str) -> Stubber:
        return self.stubs[service]

    def collector(self, **kwargs: Any) -> AwsInventoryCollector:
        kwargs.setdefault("sleeper", self.sleeps.append)
        # The IAM/S3/Lambda tests predate the EC2 inventory; they select the three
        # services explicitly so that no EC2 responses need to be queued.
        kwargs.setdefault("services", ("iam", "s3", "lambda"))
        return AwsInventoryCollector(self.session, REGION, **kwargs)

    def assert_all_consumed(self) -> None:
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()


def build_clients(monkeypatch: pytest.MonkeyPatch) -> Clients:
    """Stubbed clients for every service the collector knows (shared with the EC2 tests)."""
    session = boto3.session.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # pragma: allowlist secret
        region_name=REGION,
    )
    built = {name: session.client(name) for name in ("sts", "iam", "s3", "lambda", "ec2")}
    stubs = {name: Stubber(client) for name, client in built.items()}
    for stub in stubs.values():
        stub.activate()
    # The collector asks the session for clients (per service and region); hand it
    # the stubbed ones regardless of the keyword arguments it passes.
    monkeypatch.setattr(session, "client", lambda name, **_: built[name])
    return Clients(session=session, stubs=stubs)


@pytest.fixture
def clients(monkeypatch: pytest.MonkeyPatch) -> Clients:
    return build_clients(monkeypatch)


# ---------------------------------------------------------------------------
# response builders
# ---------------------------------------------------------------------------


def stub_identity(clients: Clients, arn: str = SCANNER_ARN) -> None:
    clients["sts"].add_response(
        "get_caller_identity",
        {"UserId": "AIDAEXAMPLE000000001", "Account": ACCOUNT, "Arn": arn},
        {},
    )


def authorization_page(
    *,
    users: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    roles: list[dict[str, Any]] | None = None,
    policies: list[dict[str, Any]] | None = None,
    marker: str | None = None,
) -> dict[str, Any]:
    page: dict[str, Any] = {
        "UserDetailList": users or [],
        "GroupDetailList": groups or [],
        "RoleDetailList": roles or [],
        "Policies": policies or [],
        "IsTruncated": marker is not None,
    }
    if marker is not None:
        page["Marker"] = marker
    return page


def user_detail(name: str, **extra: Any) -> dict[str, Any]:
    detail = {
        "Path": "/",
        "UserName": name,
        "UserId": "AIDAEXAMPLE000000002",
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": "2025-01-10T09:00:00Z",
        "UserPolicyList": [],
        "GroupList": [],
        "AttachedManagedPolicies": [],
    }
    detail.update(extra)
    return detail


def group_detail(name: str, **extra: Any) -> dict[str, Any]:
    detail = {
        "Path": "/",
        "GroupName": name,
        "GroupId": "AGPAEXAMPLE000000001",
        "Arn": f"arn:aws:iam::{ACCOUNT}:group/{name}",
        "CreateDate": "2025-01-10T09:00:00Z",
        "GroupPolicyList": [],
        "AttachedManagedPolicies": [],
    }
    detail.update(extra)
    return detail


def role_detail(name: str, **extra: Any) -> dict[str, Any]:
    detail = {
        "Path": "/service-role/",
        "RoleName": name,
        "RoleId": "AROAEXAMPLE000000001",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/service-role/{name}",
        "CreateDate": "2025-01-10T09:00:00Z",
        "AssumeRolePolicyDocument": encoded(LAMBDA_TRUST),
        "RolePolicyList": [],
        "AttachedManagedPolicies": [],
    }
    detail.update(extra)
    return detail


def managed_policy_detail(arn: str, document: dict[str, Any], **extra: Any) -> dict[str, Any]:
    detail = {
        "PolicyName": arn.rsplit("/", 1)[-1],
        "PolicyId": "ANPAEXAMPLE000000001",
        "Arn": arn,
        "Path": "/",
        "DefaultVersionId": "v2",
        "AttachmentCount": 1,
        "PolicyVersionList": [
            {"Document": encoded(document), "VersionId": "v2", "IsDefaultVersion": True}
        ],
    }
    detail.update(extra)
    return detail


def stub_user_lookups(
    clients: Clients,
    name: str,
    *,
    keys: list[tuple[str, str]] = (),
    mfa: bool = False,
    console: bool | None = False,
) -> None:
    """Queue the three per-user calls in the order the collector makes them."""
    iam = clients["iam"]
    iam.add_response(
        "list_access_keys",
        {
            "AccessKeyMetadata": [
                {
                    "UserName": name,
                    "AccessKeyId": key_id,
                    "Status": status,
                    "CreateDate": "2025-01-10T09:00:00Z",
                }
                for key_id, status in keys
            ]
        },
        {"UserName": name},
    )
    devices = (
        [
            {
                "UserName": name,
                "SerialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/{name}",
                "EnableDate": "2025-01-10T09:00:00Z",
            }
        ]
        if mfa
        else []
    )
    iam.add_response("list_mfa_devices", {"MFADevices": devices}, {"UserName": name})
    if console is True:
        iam.add_response(
            "get_login_profile",
            {"LoginProfile": {"UserName": name, "CreateDate": "2025-01-10T09:00:00Z"}},
            {"UserName": name},
        )
    elif console is False:
        iam.add_client_error(
            "get_login_profile",
            "NoSuchEntity",
            "no login profile",
            404,
            expected_params={"UserName": name},
        )
    else:
        iam.add_client_error(
            "get_login_profile", "AccessDenied", "denied", 403, expected_params={"UserName": name}
        )


def stub_list_buckets(clients: Clients, *names: str) -> None:
    clients["s3"].add_response(
        "list_buckets",
        {
            "Buckets": [{"Name": name, "CreationDate": "2025-01-01T00:00:00Z"} for name in names],
            "Owner": {"ID": "owner-id"},
        },
        {},
    )


def stub_bucket_details(
    clients: Clients,
    name: str,
    *,
    location: str | None = None,
    policy: dict[str, Any] | None = None,
    pab: bool | None = True,
    grants: list[dict[str, Any]] | None = None,
    encryption: str | None = "AES256",
    tags: dict[str, str] | None = None,
) -> None:
    """Queue the per-bucket calls in collector order; ``None`` means "not configured"."""
    s3 = clients["s3"]
    params = {"Bucket": name}
    s3.add_response(
        "get_bucket_location", {"LocationConstraint": location} if location else {}, params
    )
    if policy is None:
        s3.add_client_error(
            "get_bucket_policy", "NoSuchBucketPolicy", "none", 404, expected_params=params
        )
    else:
        s3.add_response("get_bucket_policy", {"Policy": json.dumps(policy)}, params)
    if pab is None:
        s3.add_client_error("get_public_access_block", NO_PAB, "none", 404, expected_params=params)
    else:
        s3.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": pab,
                    "IgnorePublicAcls": pab,
                    "BlockPublicPolicy": pab,
                    "RestrictPublicBuckets": pab,
                }
            },
            params,
        )
    s3.add_response("get_bucket_acl", {"Owner": {"ID": "owner-id"}, "Grants": grants or []}, params)
    if encryption is None:
        s3.add_client_error("get_bucket_encryption", NO_SSE, "none", 404, expected_params=params)
    else:
        s3.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": encryption}}]
                }
            },
            params,
        )
    if tags is None:
        s3.add_client_error(
            "get_bucket_tagging", "NoSuchTagSet", "none", 404, expected_params=params
        )
    else:
        s3.add_response(
            "get_bucket_tagging",
            {"TagSet": [{"Key": key, "Value": value} for key, value in tags.items()]},
            params,
        )


def function_summary(name: str, role: str, **extra: Any) -> dict[str, Any]:
    summary = {
        "FunctionName": name,
        "FunctionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}",
        "Runtime": "python3.12",
        "Role": role,
    }
    summary.update(extra)
    return summary


def stub_function_details(
    clients: Clients,
    name: str,
    *,
    policy: dict[str, Any] | None = None,
    tags: dict[str, str] | None = None,
) -> None:
    lam = clients["lambda"]
    if policy is None:
        lam.add_client_error(
            "get_policy",
            "ResourceNotFoundException",
            "none",
            404,
            expected_params={"FunctionName": name},
        )
    else:
        lam.add_response(
            "get_policy", {"Policy": json.dumps(policy), "RevisionId": "1"}, {"FunctionName": name}
        )
    lam.add_response(
        "list_tags",
        {"Tags": tags or {}},
        {"Resource": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"},
    )


def stub_empty_services(clients: Clients, *services: str) -> None:
    """Queue empty primary listings for the given services."""
    if "iam" in services:
        clients["iam"].add_response("get_account_authorization_details", authorization_page(), {})
    if "s3" in services:
        stub_list_buckets(clients)
    if "lambda" in services:
        clients["lambda"].add_response("list_functions", {"Functions": []}, {})


def coverage(snapshot: dict[str, Any], service: str) -> dict[str, Any]:
    return snapshot["coverage"]["services"][service]


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_two_page_authorization_details_are_merged_and_snapshot_parses(clients: Clients) -> None:
    stub_identity(clients)
    custom_arn = f"arn:aws:iam::{ACCOUNT}:policy/analyst-read-only"
    boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/boundary"

    # botocore decodes stubbed policy strings in place, so every use needs its own dict.
    def inline() -> dict[str, str]:
        return {"PolicyName": "inline-read", "PolicyDocument": encoded(ALLOW_S3_READ)}

    iam = clients["iam"]
    # Page 1 holds the users and the first policy; page 2 holds groups, roles and the rest.
    iam.add_response(
        "get_account_authorization_details",
        authorization_page(
            users=[
                user_detail(
                    "alice",
                    GroupList=["data-analysts"],
                    UserPolicyList=[inline()],
                    AttachedManagedPolicies=[
                        {"PolicyName": "analyst-read-only", "PolicyArn": custom_arn}
                    ],
                    PermissionsBoundary={
                        "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                        "PermissionsBoundaryArn": boundary_arn,
                    },
                    Tags=[{"Key": "team", "Value": "security"}],
                ),
                user_detail(
                    "bob", UserId="AIDAEXAMPLE000000003", Arn=f"arn:aws:iam::{ACCOUNT}:user/bob"
                ),
            ],
            policies=[managed_policy_detail(custom_arn, ALLOW_S3_READ)],
            marker="page-2",
        ),
        {},
    )
    iam.add_response(
        "get_account_authorization_details",
        authorization_page(
            groups=[
                group_detail(
                    "data-analysts",
                    AttachedManagedPolicies=[
                        {"PolicyName": "analyst-read-only", "PolicyArn": custom_arn}
                    ],
                )
            ],
            roles=[
                role_detail(
                    "lambda-exec",
                    RolePolicyList=[inline()],
                    Tags=[{"Key": "owner", "Value": "platform"}],
                    RoleLastUsed={"LastUsedDate": "2025-02-01T00:00:00Z", "Region": REGION},
                )
            ],
            policies=[
                managed_policy_detail(boundary_arn, ALLOW_S3_READ, PolicyId="ANPAEXAMPLE000000002")
            ],
        ),
        {"Marker": "page-2"},
    )
    stub_user_lookups(
        clients, "alice", keys=[("SYNTHETIC-KEY-ID-0001", "Active")], mfa=True, console=True
    )
    stub_user_lookups(clients, "bob", console=False)

    stub_list_buckets(clients, "legacy-backups")
    stub_bucket_details(
        clients,
        "legacy-backups",
        location="eu-west-1",
        policy=PUBLIC_READ_BUCKET_POLICY,
        pab=False,
        grants=[{"Grantee": {"Type": "Group", "URI": ALL_USERS}, "Permission": "READ"}],
        encryption="aws:kms",
        tags={"DataClassification": "High", "owner": "dba"},
    )

    role_arn = f"arn:aws:iam::{ACCOUNT}:role/service-role/lambda-exec"
    clients["lambda"].add_response(
        "list_functions",
        {
            "Functions": [function_summary("resizer", role_arn, Description="resizes images")],
            "NextMarker": "m2",
        },
        {},
    )
    clients["lambda"].add_response(
        "list_functions", {"Functions": [function_summary("webhook", role_arn)]}, {"Marker": "m2"}
    )
    stub_function_details(clients, "resizer", tags={"env": "prod"})
    stub_function_details(
        clients,
        "webhook",
        policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "lambda:InvokeFunction",
                    "Resource": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:webhook",
                }
            ],
        },
    )

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    # schema envelope
    assert snapshot["schema_version"] == "1.0"
    assert snapshot["account_id"] == ACCOUNT
    metadata = snapshot["metadata"]
    assert metadata["synthetic"] is False
    assert metadata["source"] == "aws-scan"
    assert metadata["generator"] == "attackpath aws-scan"
    assert metadata["regions"] == [REGION]
    assert metadata["generated_at"].endswith("Z") and "T" in metadata["generated_at"]
    assert {name: entry["status"] for name, entry in snapshot["coverage"]["services"].items()} == {
        "iam": "complete",
        "s3": "complete",
        "lambda": "complete",
        "ec2": "missing",  # not requested by this test's service selection
    }

    # IAM entities from both pages were merged
    users = {user["name"]: user for user in snapshot["users"]}
    assert set(users) == {"alice", "bob"}
    alice = users["alice"]
    assert alice["groups"] == ["data-analysts"]
    assert alice["inline_policies"]["inline-read"] == ALLOW_S3_READ
    assert alice["attached_policies"] == [custom_arn]
    assert alice["permissions_boundary"] == boundary_arn
    assert alice["tags"] == {"team": "security"}
    assert alice["access_keys"] == [
        {"key_id": "SYNTHETIC-KEY-ID-0001", "status": "Active", "created": "2025-01-10T09:00:00Z"}
    ]
    assert alice["mfa_enabled"] is True and alice["console_access"] is True
    assert users["bob"]["access_keys"] == []
    assert users["bob"]["mfa_enabled"] is False and users["bob"]["console_access"] is False
    assert [group["name"] for group in snapshot["groups"]] == ["data-analysts"]
    assert snapshot["groups"][0]["attached_policies"] == [custom_arn]
    (role,) = snapshot["roles"]
    assert role["name"] == "lambda-exec" and role["path"] == "/service-role/"
    assert role["trust_policy"] == LAMBDA_TRUST
    assert role["inline_policies"] == {"inline-read": ALLOW_S3_READ}
    assert role["tags"] == {"owner": "platform"}
    assert role["last_used"] == "2025-02-01T00:00:00Z"
    policies = {policy["arn"]: policy for policy in snapshot["managed_policies"]}
    assert set(policies) == {custom_arn, boundary_arn}
    assert policies[custom_arn]["document"] == ALLOW_S3_READ
    assert policies[custom_arn]["is_aws_managed"] is False
    assert policies[custom_arn]["default_version_id"] == "v2"
    assert policies[custom_arn]["attachment_count"] == 1

    # S3
    (bucket,) = snapshot["s3_buckets"]
    assert bucket["name"] == "legacy-backups"
    assert bucket["arn"] == "arn:aws:s3:::legacy-backups"
    assert bucket["region"] == "eu-west-1"
    assert bucket["bucket_policy"] == PUBLIC_READ_BUCKET_POLICY
    assert bucket["public_access_block"] == {
        "block_public_acls": False,
        "ignore_public_acls": False,
        "block_public_policy": False,
        "restrict_public_buckets": False,
    }
    assert bucket["acl_public_read"] is True and bucket["acl_public_write"] is False
    assert bucket["encryption"] == "aws:kms"
    assert bucket["sensitivity"] == "high"
    assert bucket["tags"] == {"DataClassification": "High", "owner": "dba"}

    # Lambda, paginated
    functions = {fn["name"]: fn for fn in snapshot["lambda_functions"]}
    assert set(functions) == {"resizer", "webhook"}
    assert functions["resizer"]["role_arn"] == role_arn
    assert functions["resizer"]["region"] == REGION
    assert functions["resizer"]["runtime"] == "python3.12"
    assert functions["resizer"]["description"] == "resizes images"
    assert functions["resizer"]["resource_policy"] is None
    assert functions["resizer"]["tags"] == {"env": "prod"}
    assert functions["webhook"]["resource_policy"]["Statement"][0]["Principal"] == "*"

    # the document round-trips through JSON and the strict parser
    env = parse_environment(json.loads(json.dumps(snapshot)), "test")
    assert env.summary() == {
        "users": 2,
        "groups": 1,
        "roles": 1,
        "managed_policies": 2,
        "s3_buckets": 1,
        "lambda_functions": 2,
        "ec2_instances": 0,
        "security_groups": 0,
        "external_principals": 0,
    }
    assert not env.coverage.is_complete  # ec2 was not requested, so it is reported missing
    assert env.coverage.status_of("iam").value == "complete"
    assert clients.sleeps == []


def test_throttling_is_retried_with_backoff_and_is_not_a_gap(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "lambda")
    s3 = clients["s3"]
    s3.add_client_error("list_buckets", "Throttling", "Rate exceeded", 400)
    s3.add_client_error("list_buckets", "SlowDown", "Please reduce your request rate", 503)
    stub_list_buckets(clients, "quiet-bucket")
    stub_bucket_details(clients, "quiet-bucket")

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    assert [bucket["name"] for bucket in snapshot["s3_buckets"]] == ["quiet-bucket"]
    assert coverage(snapshot, "s3") == {"status": "complete", "notes": []}
    assert clients.sleeps == [0.5, 1.0]


def test_throttling_exhaustion_records_a_note_and_continues(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "lambda")
    stub_list_buckets(clients, "busy-bucket")
    s3 = clients["s3"]
    s3.add_response("get_bucket_location", {}, {"Bucket": "busy-bucket"})
    s3.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", "none", 404)
    s3.add_client_error("get_public_access_block", NO_PAB, "none", 404)
    s3.add_client_error("get_bucket_acl", "Throttling", "Rate exceeded", 400)
    s3.add_client_error("get_bucket_acl", "Throttling", "Rate exceeded", 400)
    s3.add_client_error("get_bucket_encryption", NO_SSE, "none", 404)
    s3.add_client_error("get_bucket_tagging", "NoSuchTagSet", "none", 404)

    snapshot = clients.collector(max_attempts=2).collect()
    clients.assert_all_consumed()

    (bucket,) = snapshot["s3_buckets"]
    assert bucket["acl_public_read"] is None and bucket["acl_public_write"] is None
    assert clients.sleeps == [0.5]
    entry = coverage(snapshot, "s3")
    assert entry["status"] == "partial"
    (note,) = entry["notes"]
    assert "Throttling on s3:GetBucketAcl for bucket busy-bucket" in note
    assert "gave up after 2 attempts" in note


def test_access_denied_on_list_functions_marks_lambda_missing(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "s3")
    clients["lambda"].add_client_error(
        "list_functions",
        "AccessDeniedException",
        "User is not authorized to perform: lambda:ListFunctions",
        403,
    )

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    assert snapshot["lambda_functions"] == []
    entry = coverage(snapshot, "lambda")
    assert entry["status"] == "missing"
    (note,) = entry["notes"]
    assert "lambda:ListFunctions" in note and "AccessDeniedException" in note
    # the other services are unaffected
    assert coverage(snapshot, "iam")["status"] == "complete"
    assert coverage(snapshot, "s3")["status"] == "complete"
    env = parse_environment(snapshot, "test")
    # ec2 was not requested by this test's service selection, so it is reported missing too.
    assert [name for name, _ in env.coverage.incomplete_services()] == ["ec2", "lambda"]


def test_access_denied_on_primary_iam_listing_marks_iam_missing(clients: Clients) -> None:
    stub_identity(clients)
    clients["iam"].add_client_error(
        "get_account_authorization_details", "AccessDenied", "nope", 403
    )
    stub_empty_services(clients, "s3", "lambda")

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    assert (
        snapshot["users"] == [] and snapshot["roles"] == [] and snapshot["managed_policies"] == []
    )
    entry = coverage(snapshot, "iam")
    assert entry["status"] == "missing"
    assert "iam:GetAccountAuthorizationDetails" in entry["notes"][0]


def test_access_denied_on_per_resource_call_is_a_recorded_gap(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "lambda")
    stub_list_buckets(clients, "secret-bucket", "other-bucket")
    s3 = clients["s3"]
    s3.add_response("get_bucket_location", {}, {"Bucket": "secret-bucket"})
    s3.add_client_error("get_bucket_policy", "AccessDenied", "Access Denied", 403)
    s3.add_client_error("get_public_access_block", NO_PAB, "none", 404)
    s3.add_response(
        "get_bucket_acl", {"Owner": {"ID": "o"}, "Grants": []}, {"Bucket": "secret-bucket"}
    )
    s3.add_client_error("get_bucket_encryption", NO_SSE, "none", 404)
    s3.add_client_error("get_bucket_tagging", "NoSuchTagSet", "none", 404)
    stub_bucket_details(clients, "other-bucket")

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    buckets = {bucket["name"]: bucket for bucket in snapshot["s3_buckets"]}
    assert buckets["secret-bucket"]["bucket_policy"] is None
    assert buckets["secret-bucket"]["acl_public_read"] is False
    entry = coverage(snapshot, "s3")
    assert entry["status"] == "partial"
    assert entry["notes"] == ["AccessDenied on s3:GetBucketPolicy for bucket secret-bucket"]


def test_gaps_for_many_resources_are_aggregated_into_one_note(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "s3")
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/r"
    names = [f"fn-{i}" for i in range(5)]
    clients["lambda"].add_response(
        "list_functions", {"Functions": [function_summary(name, role_arn) for name in names]}, {}
    )
    for name in names:
        clients["lambda"].add_client_error(
            "get_policy",
            "ResourceNotFoundException",
            "none",
            404,
            expected_params={"FunctionName": name},
        )
        clients["lambda"].add_client_error("list_tags", "AccessDeniedException", "denied", 403)

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    assert len(snapshot["lambda_functions"]) == 5
    assert all(fn["tags"] == {} for fn in snapshot["lambda_functions"])
    entry = coverage(snapshot, "lambda")
    assert entry["status"] == "partial"
    (note,) = entry["notes"]
    assert note.startswith(
        "AccessDeniedException on lambda:ListTags for 5 resources (function fn-0, "
    )
    assert note.endswith(", ...)")


def test_missing_bucket_policy_and_public_access_block_are_nulls_not_gaps(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "lambda")
    stub_list_buckets(clients, "plain-bucket")
    stub_bucket_details(clients, "plain-bucket", policy=None, pab=None, encryption=None, tags=None)

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    (bucket,) = snapshot["s3_buckets"]
    assert bucket["bucket_policy"] is None
    assert bucket["public_access_block"] is None
    assert bucket["encryption"] is None
    assert bucket["tags"] == {}
    assert "sensitivity" not in bucket
    assert bucket["region"] == "us-east-1"  # empty LocationConstraint means us-east-1
    assert coverage(snapshot, "s3") == {"status": "complete", "notes": []}
    env = parse_environment(snapshot, "test")
    assert env.s3_buckets[0].bucket_policy is None
    assert env.s3_buckets[0].public_access_block is None


def test_lambda_without_resource_policy_is_null_not_gap(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "s3")
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/r"
    clients["lambda"].add_response(
        "list_functions", {"Functions": [function_summary("private", role_arn)]}, {}
    )
    stub_function_details(clients, "private", policy=None)

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    assert snapshot["lambda_functions"][0]["resource_policy"] is None
    assert coverage(snapshot, "lambda") == {"status": "complete", "notes": []}


def test_acl_grants_to_authenticated_users_count_as_public(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam", "lambda")
    stub_list_buckets(clients, "acl-bucket")
    stub_bucket_details(
        clients,
        "acl-bucket",
        location="EU",
        grants=[
            {"Grantee": {"Type": "CanonicalUser", "ID": "owner-id"}, "Permission": "FULL_CONTROL"},
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "https://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                },
                "Permission": "WRITE",
            },
        ],
        tags={"sensitivity": "Medium"},
    )

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    (bucket,) = snapshot["s3_buckets"]
    assert bucket["acl_public_read"] is False
    assert bucket["acl_public_write"] is True
    assert bucket["region"] == "eu-west-1"  # legacy "EU" constraint
    assert bucket["sensitivity"] == "medium"


def test_unresolved_attached_policy_is_fetched_with_get_policy_version(clients: Clients) -> None:
    stub_identity(clients)
    aws_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam = clients["iam"]
    iam.add_response(
        "get_account_authorization_details",
        authorization_page(
            users=[
                user_detail(
                    "carol",
                    AttachedManagedPolicies=[
                        {"PolicyName": "ReadOnlyAccess", "PolicyArn": aws_arn}
                    ],
                )
            ]
        ),
        {},
    )
    stub_user_lookups(clients, "carol")
    iam.add_response(
        "get_policy",
        {
            "Policy": {
                "PolicyName": "ReadOnlyAccess",
                "Arn": aws_arn,
                "DefaultVersionId": "v7",
                "AttachmentCount": 3,
            }
        },
        {"PolicyArn": aws_arn},
    )
    iam.add_response(
        "get_policy_version",
        {
            "PolicyVersion": {
                "Document": encoded(ALLOW_S3_READ),
                "VersionId": "v7",
                "IsDefaultVersion": True,
            }
        },
        {"PolicyArn": aws_arn, "VersionId": "v7"},
    )
    stub_empty_services(clients, "s3", "lambda")

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    (policy,) = snapshot["managed_policies"]
    assert policy == {
        "arn": aws_arn,
        "name": "ReadOnlyAccess",
        "document": ALLOW_S3_READ,
        "is_aws_managed": True,
        "attachment_count": 3,
        "default_version_id": "v7",
    }
    assert coverage(snapshot, "iam")["status"] == "complete"


def test_policy_without_default_version_document_falls_back_to_get_policy_version(
    clients: Clients,
) -> None:
    stub_identity(clients)
    arn = f"arn:aws:iam::{ACCOUNT}:policy/trimmed"
    iam = clients["iam"]
    iam.add_response(
        "get_account_authorization_details",
        authorization_page(
            policies=[managed_policy_detail(arn, ALLOW_S3_READ, PolicyVersionList=[])]
        ),
        {},
    )
    iam.add_response(
        "get_policy_version",
        {
            "PolicyVersion": {
                "Document": encoded(ALLOW_S3_READ),
                "VersionId": "v2",
                "IsDefaultVersion": True,
            }
        },
        {"PolicyArn": arn, "VersionId": "v2"},
    )
    stub_empty_services(clients, "s3", "lambda")

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    assert snapshot["managed_policies"][0]["document"] == ALLOW_S3_READ


def test_per_user_failures_degrade_iam_to_partial_but_keep_the_user(clients: Clients) -> None:
    stub_identity(clients)
    clients["iam"].add_response(
        "get_account_authorization_details", authorization_page(users=[user_detail("dave")]), {}
    )
    iam = clients["iam"]
    iam.add_client_error("list_access_keys", "AccessDenied", "denied", 403)
    iam.add_client_error("list_mfa_devices", "ServiceFailure", "internal", 500)
    iam.add_client_error("get_login_profile", "AccessDenied", "denied", 403)
    stub_empty_services(clients, "s3", "lambda")

    snapshot = clients.collector().collect()
    clients.assert_all_consumed()

    (user,) = snapshot["users"]
    assert user["access_keys"] == []
    assert user["mfa_enabled"] is None
    assert user["console_access"] is None
    entry = coverage(snapshot, "iam")
    assert entry["status"] == "partial"
    assert entry["notes"] == [
        "AccessDenied on iam:ListAccessKeys for user dave",
        "ServiceFailure on iam:ListMFADevices for user dave",
        "AccessDenied on iam:GetLoginProfile for user dave",
    ]


def test_unrequested_services_are_reported_missing(clients: Clients) -> None:
    stub_identity(clients)
    stub_empty_services(clients, "iam")

    snapshot = clients.collector(services=("iam",)).collect()
    clients.assert_all_consumed()

    assert coverage(snapshot, "iam")["status"] == "complete"
    assert coverage(snapshot, "s3")["status"] == "missing"
    assert coverage(snapshot, "lambda")["status"] == "missing"
    assert "not requested" in coverage(snapshot, "s3")["notes"][0]
    assert snapshot["coverage"]["notes"] == []
    assert snapshot["s3_buckets"] == [] and snapshot["lambda_functions"] == []


def test_identity_failure_raises_aws_scan_error(clients: Clients) -> None:
    clients["sts"].add_client_error("get_caller_identity", "InvalidClientTokenId", "bad token", 403)
    with pytest.raises(
        AwsScanError, match="sts:GetCallerIdentity failed \\(InvalidClientTokenId\\)"
    ):
        clients.collector().collect()


def test_root_identity_is_refused(clients: Clients) -> None:
    stub_identity(clients, arn=f"arn:aws:iam::{ACCOUNT}:root")
    with pytest.raises(AwsScanError, match="root"):
        clients.collector().collect()


def test_unknown_service_and_bad_attempts_are_rejected(clients: Clients) -> None:
    with pytest.raises(AwsScanError, match="unsupported service"):
        clients.collector(services=("iam", "rds"))
    with pytest.raises(AwsScanError, match="at least one service"):
        clients.collector(services=())
    with pytest.raises(AwsScanError, match="max_attempts"):
        clients.collector(max_attempts=0)
    assert clients.collector(services=("Lambda", "iam", "iam")).services == ("iam", "lambda")


def test_decode_policy_accepts_dicts_json_and_url_encoded_json() -> None:
    assert _decode_policy(ALLOW_S3_READ) == ALLOW_S3_READ
    assert _decode_policy(json.dumps(ALLOW_S3_READ)) == ALLOW_S3_READ
    assert _decode_policy(encoded(ALLOW_S3_READ)) == ALLOW_S3_READ
    # a literal percent sign inside plain JSON must survive (no blind unquoting)
    tricky = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "100%25", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }
    assert _decode_policy(json.dumps(tricky)) == tricky
    assert _decode_policy("") is None
    assert _decode_policy("not json") is None
    assert _decode_policy('["list"]') is None
    assert _decode_policy(None) is None
