"""Reusable remediation and verification text.

All suggested commands are read-only (``get``, ``simulate``, ``list``). The tool
never applies changes; recommendations must be reviewed and validated before use.
"""

from __future__ import annotations

from collections.abc import Iterable


def rerun_step(check_id: str, subject: str) -> str:
    return (
        f"Re-run the analyzer on a fresh snapshot and confirm that no {check_id} finding "
        f"remains for {subject}."
    )


def simulate_step(principal_arn: str, actions: Iterable[str], resource: str) -> str:
    names = " ".join(actions)
    return (
        "Simulate the permission with the IAM policy simulator (read-only): "
        f"aws iam simulate-principal-policy --policy-source-arn {principal_arn} "
        f"--action-names {names} --resource-arns {resource} ; expect implicitDeny or explicitDeny."
    )


def get_role_step(role_name: str) -> str:
    return (
        f"Confirm the trust policy: aws iam get-role --role-name {role_name} "
        "--query Role.AssumeRolePolicyDocument"
    )


def bucket_policy_status_step(bucket_name: str) -> str:
    return (
        f"Confirm the bucket is not public: aws s3api get-bucket-policy-status --bucket {bucket_name} "
        "(expect IsPublic=false) and aws s3api get-public-access-block --bucket "
        f"{bucket_name} (expect all four settings true)."
    )


def access_analyzer_step() -> str:
    return (
        "If IAM Access Analyzer is enabled, confirm that no external-access finding remains "
        "for the resource (aws accessanalyzer list-findings)."
    )


def least_privilege_steps(principal_label: str) -> tuple[str, ...]:
    return (
        f"Inventory the actions {principal_label} actually uses (CloudTrail, IAM Access Analyzer "
        "policy generation, or IAM last-accessed information).",
        "Replace the broad statement with explicit actions scoped to the specific resource ARNs "
        "the workflow needs; keep separate statements per service.",
        "Add a permissions boundary to the principal if its policies are managed by delegated "
        "administrators.",
        "Roll the change out through infrastructure-as-code and review it before deployment.",
    )


POLICY_ASSUMPTIONS_GENERIC: tuple[str, ...] = (
    "The suggested policy is a template: replace placeholder ARNs with the resources the "
    "workflow genuinely needs.",
    "Validate the policy with IAM Access Analyzer policy checks and the policy simulator "
    "before deploying it; test in a non-production account first.",
    "Legitimate functionality that depends on the removed permissions must be identified "
    "from usage data before the change is applied.",
)
