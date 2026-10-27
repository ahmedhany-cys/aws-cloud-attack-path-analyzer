#!/usr/bin/env python3
"""Measure analysis time on generated synthetic environments of increasing size.

The generator is deterministic (seeded) and produces a mix of scoped workload roles,
human users with long-lived keys, a few administrative identities, account-root
trusts, and buckets of varying sensitivity, so that every check and the path search
have work to do. Nothing here touches AWS.

Usage: python scripts/benchmark.py [--sizes 100,500,2000] [--repeat 3]
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attackpath.analysis.engine import analyze  # noqa: E402
from attackpath.parser.environment_parser import parse_environment  # noqa: E402

ACCOUNT = "111111111111"


def generate(principals: int, seed: int = 7) -> dict[str, Any]:
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security material
    bucket_count = max(5, principals // 10)
    buckets = []
    for i in range(bucket_count):
        sensitivity = rng.choices(["high", "medium", "low"], weights=[2, 3, 5])[0]
        bucket: dict[str, Any] = {
            "name": f"bucket-{i:05d}",
            "sensitivity": sensitivity,
            "public_access_block": {
                "block_public_acls": True,
                "ignore_public_acls": True,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            },
        }
        if rng.random() < 0.02:
            bucket["bucket_policy"] = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::bucket-{i:05d}/*",
                    }
                ],
            }
            bucket["public_access_block"] = None
        buckets.append(bucket)

    users = []
    roles = []
    functions = []
    role_count = int(principals * 0.7)
    user_count = principals - role_count
    for i in range(role_count):
        kind = rng.random()
        target = f"bucket-{rng.randrange(bucket_count):05d}"
        if kind < 0.75:
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{target}/*"},
                    {"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "*"},
                ],
            }
            trust_principal: dict[str, str] = {"Service": "lambda.amazonaws.com"}
        elif kind < 0.9:
            policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
            }
            trust_principal = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
        elif kind < 0.97:
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{target}/*",
                        "Condition": {"StringEquals": {"aws:SourceVpce": f"vpce-{i:08x}"}},
                    }
                ],
            }
            trust_principal = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
        else:
            policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            trust_principal = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
        roles.append(
            {
                "name": f"role-{i:05d}",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}],
                },
                "inline_policies": {"p": policy},
            }
        )
        if trust_principal.get("Service") and rng.random() < 0.5:
            functions.append({"name": f"fn-{i:05d}", "role_arn": f"arn:aws:iam::{ACCOUNT}:role/role-{i:05d}"})

    for i in range(user_count):
        kind = rng.random()
        if kind < 0.6:
            policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": f"arn:aws:s3:::bucket-{rng.randrange(bucket_count):05d}*"}],
            }
        elif kind < 0.85:
            policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{ACCOUNT}:role/role-{rng.randrange(role_count):05d}"}],
            }
        elif kind < 0.95:
            policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
            }
        else:
            policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        users.append(
            {
                "name": f"user-{i:05d}",
                "inline_policies": {"p": policy},
                "access_keys": [{"key_id": f"SYNTHETIC-KEY-{i:05d}", "status": "Active"}] if rng.random() < 0.5 else [],
                "mfa_enabled": rng.random() < 0.5,
                "console_access": True,
            }
        )

    return {
        "schema_version": "1.0",
        "metadata": {"name": f"benchmark-{principals}", "synthetic": True},
        "account_id": ACCOUNT,
        "coverage": {"services": {"iam": "complete", "s3": "complete", "lambda": "complete"}},
        "users": users,
        "roles": roles,
        "s3_buckets": buckets,
        "lambda_functions": functions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="100,500,2000", help="comma-separated principal counts")
    parser.add_argument("--repeat", type=int, default=3, help="runs per size (median reported)")
    args = parser.parse_args(argv)
    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    print(f"{'principals':>10} {'buckets':>8} {'edges':>8} {'paths':>7} {'findings':>9} {'median s':>9} {'max s':>7}")
    for size in sizes:
        env = parse_environment(generate(size), f"benchmark-{size}")
        timings: list[float] = []
        result = None
        for _ in range(args.repeat):
            started = time.perf_counter()
            result = analyze(env)
            timings.append(time.perf_counter() - started)
        assert result is not None  # noqa: S101 - script-level sanity check
        print(
            f"{env.principal_count:>10} {len(env.s3_buckets):>8} {len(result.graph.edges):>8} "
            f"{len(result.paths.paths):>7} {len(result.findings):>9} {statistics.median(timings):>9.2f} {max(timings):>7.2f}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
