"""Read-only safeguards for the optional AWS adapter.

The adapter must never change anything in an account. Instead of trusting every
call site to stay read-only, :func:`install_safeguards` hooks botocore's
``before-call`` event on the session so that any operation outside the frozen
allow list below is rejected before a request is built or signed. The same allow
list drives :func:`read_only_policy`, the minimal IAM policy a scan identity needs.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from attackpath.exceptions import SafeguardViolationError

# botocore service id -> API operation -> IAM action that authorizes it. Several
# S3 operations are authorized by an action with a different name, which is why
# the mapping is kept explicit rather than derived from the operation name.
REQUIRED_IAM_ACTIONS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        "iam": MappingProxyType(
            {
                "GetAccountAuthorizationDetails": "iam:GetAccountAuthorizationDetails",
                "ListAccessKeys": "iam:ListAccessKeys",
                "ListMFADevices": "iam:ListMFADevices",
                "GetLoginProfile": "iam:GetLoginProfile",
                "GetPolicy": "iam:GetPolicy",
                "GetPolicyVersion": "iam:GetPolicyVersion",
            }
        ),
        "s3": MappingProxyType(
            {
                "ListBuckets": "s3:ListAllMyBuckets",
                "GetBucketLocation": "s3:GetBucketLocation",
                "GetBucketPolicy": "s3:GetBucketPolicy",
                "GetBucketPolicyStatus": "s3:GetBucketPolicyStatus",
                "GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
                "GetBucketAcl": "s3:GetBucketAcl",
                "GetBucketEncryption": "s3:GetEncryptionConfiguration",
                "GetBucketTagging": "s3:GetBucketTagging",
            }
        ),
        "lambda": MappingProxyType(
            {
                "ListFunctions": "lambda:ListFunctions",
                "GetPolicy": "lambda:GetPolicy",
                "ListTags": "lambda:ListTags",
            }
        ),
        "ec2": MappingProxyType(
            {
                "DescribeInstances": "ec2:DescribeInstances",
                "DescribeSecurityGroups": "ec2:DescribeSecurityGroups",
                "DescribeRouteTables": "ec2:DescribeRouteTables",
            }
        ),
        "sts": MappingProxyType({"GetCallerIdentity": "sts:GetCallerIdentity"}),
    }
)

#: Frozen allow list: botocore service id -> operations the adapter may invoke.
READ_ONLY_OPERATIONS: Mapping[str, frozenset[str]] = MappingProxyType(
    {service: frozenset(operations) for service, operations in REQUIRED_IAM_ACTIONS.items()}
)

_HANDLER_ID = "attackpath-read-only-safeguard"
_EVENT = "before-call.*"


def is_allowed(service_id: str, operation: str) -> bool:
    """Return whether ``operation`` of ``service_id`` is on the read-only allow list."""
    return operation in READ_ONLY_OPERATIONS.get(service_id.lower(), frozenset())


def install_safeguards(session: Any) -> None:
    """Register the read-only guard on a boto3/botocore session.

    Clients created from the session afterwards inherit the handler; registering
    twice is a no-op. Clients created *before* this call are not covered, so it
    must run before any client is built.
    """
    session.events.register(_EVENT, enforce_read_only, unique_id=_HANDLER_ID)


def enforce_read_only(model: Any = None, event_name: str = "", **_: Any) -> None:
    """``before-call`` handler: raise unless the operation is on the allow list.

    Fails closed: when neither the operation model nor the event name identifies
    the call, it is refused.
    """
    service_id, operation = _identify(model, event_name)
    if not service_id or not operation:
        raise SafeguardViolationError(
            f"refusing AWS API call: operation could not be identified ({event_name or 'no event'})"
        )
    if not is_allowed(service_id, operation):
        raise SafeguardViolationError(
            f"refusing {service_id}:{operation}: not in the read-only allow list of aws-scan"
        )


def read_only_policy() -> dict[str, Any]:
    """Return the minimal IAM policy document the scan identity needs."""
    actions = sorted(
        {action for per_service in REQUIRED_IAM_ACTIONS.values() for action in per_service.values()}
    )
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AttackPathReadOnlyInventory",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            }
        ],
    }


def _identify(model: Any, event_name: str) -> tuple[str, str]:
    service_id = ""
    operation = ""
    if model is not None:
        try:
            service_id = str(model.service_model.service_id.hyphenize())
            operation = str(model.name)
        except AttributeError:
            service_id = operation = ""
    if not service_id or not operation:
        parts = event_name.split(".")
        if len(parts) >= 3 and parts[0] == "before-call":
            service_id, operation = parts[1], parts[2]
    return service_id, operation


__all__ = [
    "READ_ONLY_OPERATIONS",
    "REQUIRED_IAM_ACTIONS",
    "enforce_read_only",
    "install_safeguards",
    "is_allowed",
    "read_only_policy",
]
