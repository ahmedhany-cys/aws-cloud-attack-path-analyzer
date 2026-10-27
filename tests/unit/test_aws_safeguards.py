"""Tests for the read-only safeguards of the AWS adapter (no credentials, no network)."""

from __future__ import annotations

import pytest

from attackpath.aws.safeguards import (
    READ_ONLY_OPERATIONS,
    REQUIRED_IAM_ACTIONS,
    enforce_read_only,
    install_safeguards,
    is_allowed,
    read_only_policy,
)
from attackpath.exceptions import AwsScanError, SafeguardViolationError

boto3 = pytest.importorskip("boto3")

pytestmark = pytest.mark.aws


class _HttpAttemptedError(Exception):
    """Raised by the tripwire if a request ever reaches botocore's send phase."""


def _session():
    return boto3.session.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # pragma: allowlist secret
        region_name="us-east-1",
    )


def _tripwire(**_):
    raise _HttpAttemptedError("an HTTP request was about to be sent")


def _guarded_client(session, service):
    client = session.client(service)
    client.meta.events.register_first("before-send.*.*", _tripwire)
    return client


def test_allow_list_matches_the_specification():
    assert set(READ_ONLY_OPERATIONS) == {"iam", "s3", "lambda", "ec2", "sts"}
    assert READ_ONLY_OPERATIONS["iam"] == {
        "GetAccountAuthorizationDetails",
        "ListAccessKeys",
        "ListMFADevices",
        "GetLoginProfile",
        "GetPolicy",
        "GetPolicyVersion",
    }
    assert READ_ONLY_OPERATIONS["s3"] == {
        "ListBuckets",
        "GetBucketLocation",
        "GetBucketPolicy",
        "GetBucketPolicyStatus",
        "GetPublicAccessBlock",
        "GetBucketAcl",
        "GetBucketEncryption",
        "GetBucketTagging",
    }
    assert READ_ONLY_OPERATIONS["lambda"] == {"ListFunctions", "GetPolicy", "ListTags"}
    assert READ_ONLY_OPERATIONS["ec2"] == {
        "DescribeInstances",
        "DescribeSecurityGroups",
        "DescribeRouteTables",
    }
    assert READ_ONLY_OPERATIONS["sts"] == {"GetCallerIdentity"}


def test_allow_list_is_frozen_and_contains_only_read_operations():
    with pytest.raises(TypeError):
        READ_ONLY_OPERATIONS["rds"] = frozenset({"DescribeDBInstances"})  # type: ignore[index]
    for operations in READ_ONLY_OPERATIONS.values():
        assert isinstance(operations, frozenset)
        for operation in operations:
            assert operation.startswith(("Get", "List", "Describe")), operation


def test_allow_list_operations_exist_in_botocore_models():
    session = _session()
    for service, operations in READ_ONLY_OPERATIONS.items():
        model = session.client(service).meta.service_model
        assert operations <= set(model.operation_names), service


def test_read_only_policy_covers_every_allow_listed_operation():
    policy = read_only_policy()
    assert policy["Version"] == "2012-10-17"
    statements = policy["Statement"]
    assert all(statement["Effect"] == "Allow" for statement in statements)
    granted = {action for statement in statements for action in statement["Action"]}
    for service, operations in READ_ONLY_OPERATIONS.items():
        for operation in operations:
            assert REQUIRED_IAM_ACTIONS[service][operation] in granted, (service, operation)
    # nothing beyond the inventory calls, and nothing that can modify state
    expected = {action for actions in REQUIRED_IAM_ACTIONS.values() for action in actions.values()}
    assert granted == expected
    assert not any(
        action.split(":")[1].startswith(("Put", "Delete", "Create", "Update", "Attach"))
        for action in granted
    )


def test_read_only_policy_statement_is_parseable_by_the_analyzer():
    from attackpath.parser.policy_parser import parse_policy_document

    document = parse_policy_document(read_only_policy(), "read-only-policy")
    assert len(document.statements) == 1


def test_is_allowed_is_case_insensitive_on_service_id():
    assert is_allowed("S3", "ListBuckets")
    assert is_allowed("iam", "GetPolicy")
    assert not is_allowed("s3", "PutBucketPolicy")
    assert is_allowed("ec2", "DescribeInstances")
    assert not is_allowed("ec2", "RunInstances")
    assert not is_allowed("rds", "DescribeDBInstances")


def test_safeguard_blocks_write_operation_before_any_http_request():
    session = _session()
    install_safeguards(session)
    s3 = _guarded_client(session, "s3")

    with pytest.raises(SafeguardViolationError) as excinfo:
        s3.put_bucket_policy(Bucket="example-bucket", Policy="{}")
    assert "s3:PutBucketPolicy" in str(excinfo.value)
    assert isinstance(excinfo.value, AwsScanError)


def test_safeguard_blocks_writes_on_every_service_it_covers():
    session = _session()
    install_safeguards(session)
    iam = _guarded_client(session, "iam")
    lam = _guarded_client(session, "lambda")
    with pytest.raises(SafeguardViolationError):
        iam.create_access_key(UserName="alice")
    with pytest.raises(SafeguardViolationError):
        iam.delete_user(UserName="alice")
    with pytest.raises(SafeguardViolationError):
        lam.delete_function(FunctionName="fn")
    ec2 = _guarded_client(session, "ec2")
    with pytest.raises(SafeguardViolationError):
        ec2.terminate_instances(InstanceIds=["i-0123456789abcdef0"])
    with pytest.raises(SafeguardViolationError):
        ec2.authorize_security_group_ingress(GroupId="sg-0123456789abcdef0")


def test_safeguard_blocks_services_outside_the_allow_list_entirely():
    session = _session()
    install_safeguards(session)
    rds = _guarded_client(session, "rds")
    with pytest.raises(SafeguardViolationError):
        rds.describe_db_instances()


def test_safeguard_lets_allow_listed_operations_through_to_the_send_phase():
    session = _session()
    install_safeguards(session)
    sts = _guarded_client(session, "sts")
    s3 = _guarded_client(session, "s3")
    # The tripwire proves the guard returned None and botocore proceeded to send.
    with pytest.raises(_HttpAttemptedError):
        sts.get_caller_identity()
    with pytest.raises(_HttpAttemptedError):
        s3.get_bucket_policy(Bucket="example-bucket")


def test_install_safeguards_is_idempotent():
    session = _session()
    install_safeguards(session)
    install_safeguards(session)
    s3 = _guarded_client(session, "s3")
    with pytest.raises(SafeguardViolationError):
        s3.delete_bucket(Bucket="example-bucket")


def test_clients_created_before_installation_are_not_covered():
    # Documents the ordering requirement: install first, create clients afterwards.
    session = _session()
    early = _guarded_client(session, "s3")
    install_safeguards(session)
    late = _guarded_client(session, "s3")
    with pytest.raises(_HttpAttemptedError):
        early.delete_bucket(Bucket="example-bucket")
    with pytest.raises(SafeguardViolationError):
        late.delete_bucket(Bucket="example-bucket")


def test_handler_falls_back_to_event_name_and_fails_closed():
    assert enforce_read_only(model=None, event_name="before-call.s3.ListBuckets") is None
    with pytest.raises(SafeguardViolationError):
        enforce_read_only(model=None, event_name="before-call.s3.PutObject")
    with pytest.raises(SafeguardViolationError):
        enforce_read_only(model=None, event_name="")
    with pytest.raises(SafeguardViolationError):
        enforce_read_only(model=object(), event_name="unrelated")
