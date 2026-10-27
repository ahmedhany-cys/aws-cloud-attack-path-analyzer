#!/usr/bin/env python3
"""Derive the per-scenario fixtures from fixtures/sample_environment.json.

Each scenario is a subset of the sample environment (optionally with a small
modification, as in the remediation example). Keeping the scenarios derived from
one source prevents the fixtures from drifting apart. The output is written to
``src/attackpath/data/scenarios`` (package data used by ``attackpath validate``)
and mirrored to ``fixtures/scenarios``; a test asserts both copies are identical.

Usage: python scripts/build_scenarios.py [--check]
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "fixtures" / "sample_environment.json"
PACKAGE_DIR = ROOT / "src" / "attackpath" / "data" / "scenarios"
MIRROR_DIR = ROOT / "fixtures" / "scenarios"

FULL_PAB = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}

# name -> selection of entities from the sample environment
SCENARIOS: dict[str, dict[str, Any]] = {
    "01-overly-broad-role": {
        "description": "A role with Action * on Resource * is reported as administrative.",
        "roles": ["ops-admin-legacy"],
    },
    "02-risky-trust": {
        "description": "Anonymous trust, cross-account trust without ExternalId, and cross-account trust with ExternalId.",
        "roles": ["vendor-support-access", "partner-integration", "third-party-monitoring"],
        "managed_policies": ["arn:aws:iam::aws:policy/AmazonS3FullAccess"],
        "s3_buckets": ["finance-reports", "customer-pii-exports"],
        "external_principals": ["arn:aws:iam::222222222222:root"],
    },
    "03-passrole-broad": {
        "description": "A deployment user holds iam:PassRole on * together with Lambda write permissions.",
        "users": ["ci-deployer"],
        "roles": ["ops-admin-legacy", "lambda-image-resizer"],
        "managed_policies": [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        ],
        "s3_buckets": ["build-artifacts", "customer-pii-exports"],
        "lambda_functions": ["image-resizer"],
    },
    "04-workload-s3-access": {
        "description": "A function's execution role has S3 full access and therefore reaches a high-sensitivity bucket.",
        "roles": ["lambda-image-resizer"],
        "managed_policies": [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        ],
        "s3_buckets": ["customer-pii-exports", "thumbnail-input"],
        "lambda_functions": ["image-resizer"],
    },
    "05-public-bucket": {
        "description": "Public bucket policies: effective, mitigated by Block Public Access, and intentionally public low-sensitivity data.",
        "s3_buckets": [
            "legacy-backups",
            "archive-with-restricted-policy",
            "public-marketing-assets",
        ],
    },
    "06-explicit-deny": {
        "description": "A group grants s3:GetObject on * but an inline Deny blocks the PII bucket; the deny must win.",
        "users": ["analyst-readonly"],
        "groups": ["data-analysts"],
        "managed_policies": ["arn:aws:iam::111111111111:policy/analyst-read-only"],
        "s3_buckets": ["customer-pii-exports", "finance-reports"],
    },
    "07-unknown-condition": {
        "description": "An Allow guarded by aws:SourceVpce cannot be decided offline and is reported as indeterminate.",
        "roles": ["finance-reporting"],
        "s3_buckets": ["customer-pii-exports"],
    },
    "08-safe-configuration": {
        "description": "A least-privilege execution role scoped to its two buckets produces no high-severity finding.",
        "roles": ["lambda-thumbnailer-least-priv"],
        "managed_policies": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        "s3_buckets": ["thumbnail-input", "thumbnail-output"],
        "lambda_functions": ["thumbnailer"],
        "coverage": {"services": {"iam": "complete", "s3": "complete", "lambda": "complete"}},
    },
    "09-incomplete-inventory": {
        "description": "Unresolved managed policy, missing execution role and partial Lambda coverage produce coverage warnings.",
        "roles": ["data-pipeline-worker"],
        "lambda_functions": ["orphan-cleanup"],
    },
    "10-remediation-before": {
        "description": "A user with sts:AssumeRole on * reaches an administrative role trusted by the whole account.",
        "users": ["legacy-automation"],
        "roles": ["ops-admin-legacy"],
    },
    "10-remediation-after": {
        "description": "The same environment after scoping sts:AssumeRole and narrowing the trust policy: the path is gone.",
        "users": ["legacy-automation", "break-glass-admin"],
        "roles": ["ops-admin-legacy", "data-pipeline-worker"],
        "managed_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
        "modify": "remediate_assume_role",
    },
}


def _select(
    items: list[dict[str, Any]], key: str, wanted: list[str] | None
) -> list[dict[str, Any]]:
    if not wanted:
        return []
    by_key = {item[key]: item for item in items}
    missing = [w for w in wanted if w not in by_key]
    if missing:
        raise SystemExit(f"unknown {key} in sample environment: {missing}")
    return [copy.deepcopy(by_key[w]) for w in wanted]


def remediate_assume_role(env: dict[str, Any]) -> None:
    for user in env["users"]:
        if user["name"] == "legacy-automation":
            user["inline_policies"]["legacy"]["Statement"] = [
                {
                    "Sid": "AssumePipelineRoleOnly",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::111111111111:role/data-pipeline-worker",
                }
            ]
    for role in env["roles"]:
        if role["name"] == "ops-admin-legacy":
            role["trust_policy"]["Statement"] = [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:user/break-glass-admin"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ]
        if role["name"] == "data-pipeline-worker":
            role["attached_policies"] = []
            role["description"] = (
                "Pipeline role (managed policy replaced by the inline queue policy)"
            )


MODIFIERS = {"remediate_assume_role": remediate_assume_role}


def build(sample: dict[str, Any], name: str, spec: dict[str, Any]) -> dict[str, Any]:
    env: dict[str, Any] = {
        "schema_version": sample["schema_version"],
        "metadata": {
            "name": f"scenario {name}",
            "description": spec["description"],
            "synthetic": True,
            "source": "fixture",
            "generator": "scripts/build_scenarios.py from fixtures/sample_environment.json",
        },
        "account_id": sample["account_id"],
        "coverage": spec.get(
            "coverage", {"services": {"iam": "complete", "s3": "complete", "lambda": "complete"}}
        ),
        "external_principals": _select(
            sample["external_principals"], "arn", spec.get("external_principals")
        ),
        "managed_policies": _select(
            sample["managed_policies"], "arn", spec.get("managed_policies")
        ),
        "groups": _select(sample["groups"], "name", spec.get("groups")),
        "users": _select(sample["users"], "name", spec.get("users")),
        "roles": _select(sample["roles"], "name", spec.get("roles")),
        "s3_buckets": _select(sample["s3_buckets"], "name", spec.get("s3_buckets")),
        "lambda_functions": _select(
            sample["lambda_functions"], "name", spec.get("lambda_functions")
        ),
    }
    if name == "09-incomplete-inventory":
        env["coverage"] = sample["coverage"]
    modifier = spec.get("modify")
    if modifier:
        MODIFIERS[modifier](env)
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if the generated files differ from those on disk"
    )
    args = parser.parse_args(argv)
    sample = json.loads(SAMPLE.read_text("utf-8"))
    differences: list[str] = []
    for directory in (PACKAGE_DIR, MIRROR_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        for name, spec in SCENARIOS.items():
            path = directory / f"{name}.json"
            content = json.dumps(build(sample, name, spec), indent=2) + "\n"
            if args.check:
                if not path.exists() or path.read_text("utf-8") != content:
                    differences.append(str(path))
            else:
                path.write_text(content, encoding="utf-8")
        expected_src = PACKAGE_DIR / "expected.json"
        expected_dst = directory / "expected.json"
        if directory is MIRROR_DIR and expected_src.exists():
            if args.check:
                if not expected_dst.exists() or expected_dst.read_text(
                    "utf-8"
                ) != expected_src.read_text("utf-8"):
                    differences.append(str(expected_dst))
            else:
                expected_dst.write_text(expected_src.read_text("utf-8"), encoding="utf-8")
    if args.check:
        if differences:
            print("scenario fixtures are out of date:\n  " + "\n  ".join(differences))
            return 1
        print("scenario fixtures are up to date")
        return 0
    print(f"wrote {len(SCENARIOS)} scenario fixtures to {PACKAGE_DIR} and {MIRROR_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
