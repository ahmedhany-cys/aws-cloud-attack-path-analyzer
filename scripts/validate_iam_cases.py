#!/usr/bin/env python3
"""Validate the IAM regression corpus against the IAM policy simulator (opt-in).

For every case in ``tests/regression/iam_cases.json`` whose ``simulator.supported`` flag
is true, this script calls ``iam:SimulateCustomPolicy`` with the case's identity policies,
permissions boundary, bucket policy, resource, action and request context, and compares
the simulator's decision with the documented expectation and with this project's offline
evaluator. The script changes nothing in AWS and never modifies the corpus.

Safety:

* The only operations the script can issue are ``iam:SimulateCustomPolicy`` and
  ``sts:GetCallerIdentity``. A botocore ``before-call`` handler (same pattern as
  ``attackpath.aws.safeguards``) rejects everything else before a request is signed and
  fails closed when an operation cannot be identified.
* Root credentials are refused.
* Without ``--confirm`` the script only prints its plan and exits with status 1.
* ``boto3`` is imported lazily; nothing talks to AWS at import time.

Usage::

    python scripts/validate_iam_cases.py --profile <name> [--region us-east-1]
        [--cases tests/regression/iam_cases.json] [--output results.json] [--confirm]

Exit status: 0 when every simulated case agrees with its documented expectation and
with the offline evaluator, 1 for the plan-only mode or any disagreement, 2 for
operational errors (missing boto3, root credentials, unreadable corpus).
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import ipaddress
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attackpath.iam.evaluator import Decision, PolicyEvaluator  # noqa: E402
from attackpath.models.environment import Environment, Principal, User  # noqa: E402
from attackpath.parser.environment_parser import parse_environment  # noqa: E402

DEFAULT_CASES = ROOT / "tests" / "regression" / "iam_cases.json"
DEFAULT_REGION = "us-east-1"

#: botocore service id -> operations this script may invoke. Nothing else gets signed.
ALLOWED_OPERATIONS: dict[str, frozenset[str]] = {
    "iam": frozenset({"SimulateCustomPolicy"}),
    "sts": frozenset({"GetCallerIdentity"}),
}
API_OPERATIONS = ("sts:GetCallerIdentity", "iam:SimulateCustomPolicy")
_GUARD_ID = "iam-cases-simulator-guard"
_GUARD_EVENT = "before-call.*"

SIMULATOR_TO_CORPUS = {
    "allowed": "allowed",
    "explicitDeny": "explicit_deny",
    "implicitDeny": "implicit_deny",
}
EVALUATOR_TO_CORPUS = {
    Decision.ALLOWED: "allowed",
    Decision.EXPLICIT_DENY: "explicit_deny",
    Decision.IMPLICIT_DENY: "implicit_deny",
    Decision.INDETERMINATE: "indeterminate",
}

# SimulateCustomPolicy requires at least one identity policy. Cases whose principal has
# no identity policy (resource policy alone, boundary alone) get this placeholder: a Deny
# can never grant anything, and it names a resource that no case uses.
PLACEHOLDER_RESOURCE = "arn:aws:iam::111111111111:user/simulator-placeholder-does-not-exist"
NO_PERMISSIONS_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SimulatorPlaceholderGrantsNothing",
            "Effect": "Deny",
            "Action": "iam:DeleteUser",
            "Resource": PLACEHOLDER_RESOURCE,
        }
    ],
}

# Context keys whose simulator data type is fixed by the key name. String keys are listed
# too so that values such as a 12-digit account id are not mistaken for numbers.
_KEY_TYPES = {
    "aws:sourceip": "ip",
    "aws:vpcsourceip": "ip",
    "aws:currenttime": "date",
    "aws:tokenissuetime": "date",
    "aws:epochtime": "numeric",
    "aws:multifactorauthage": "numeric",
    "aws:multifactorauthpresent": "boolean",
    "aws:securetransport": "boolean",
    "aws:viaawsservice": "boolean",
    "aws:principalarn": "string",
    "aws:principalaccount": "string",
    "aws:principalorgid": "string",
    "aws:principaltype": "string",
    "aws:username": "string",
    "aws:userid": "string",
    "aws:sourceaccount": "string",
    "aws:sourcearn": "string",
    "aws:resourceaccount": "string",
    "aws:requestedregion": "string",
    "aws:sourcevpce": "string",
    "aws:tagkeys": "string",
}
_STRING_KEY_PREFIXES = ("aws:principaltag/", "aws:requesttag/", "aws:resourcetag/")
_NUMERIC_RE = re.compile(r"-?\d+(\.\d+)?")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?")
_CONDITION_KEY_RE = re.compile(r"aws:[A-Za-z]+(?:/[A-Za-z0-9_.:+=@-]+)?")


class ApiGuardError(RuntimeError):
    """An AWS API operation outside the allow list was attempted."""


class CorpusError(ValueError):
    """The corpus file is unusable."""


@dataclass
class CaseResult:
    case_id: str
    area: str
    status: str
    expected: str
    simulator: str
    evaluator: str
    match: str
    missing_context: list[str] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# API guard (same pattern as attackpath.aws.safeguards, with this script's allow list)
# ---------------------------------------------------------------------------


def is_allowed(service_id: str, operation: str) -> bool:
    return operation in ALLOWED_OPERATIONS.get(service_id.lower(), frozenset())


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


def enforce_allow_list(model: Any = None, event_name: str = "", **_: Any) -> None:
    """``before-call`` handler: raise unless the operation is on the allow list."""
    service_id, operation = _identify(model, event_name)
    if not service_id or not operation:
        raise ApiGuardError(
            f"refusing AWS API call: operation could not be identified ({event_name or 'no event'})"
        )
    if not is_allowed(service_id, operation):
        raise ApiGuardError(
            f"refusing {service_id}:{operation}: only {', '.join(API_OPERATIONS)} are permitted"
        )


def install_guard(session: Any) -> None:
    """Register the guard on a boto3 session before any client is created."""
    session.events.register(_GUARD_EVENT, enforce_allow_list, unique_id=_GUARD_ID)


# ---------------------------------------------------------------------------
# corpus handling
# ---------------------------------------------------------------------------


def load_cases(path: Path) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise CorpusError(f"cannot read corpus {path}: {exc}") from exc
    cases = document.get("cases") if isinstance(document, dict) else None
    if not isinstance(cases, list) or not all(isinstance(case, dict) for case in cases):
        raise CorpusError(f"{path}: expected an object with a 'cases' list")
    return [dict(case) for case in cases]


def build_environment(case: dict[str, Any]) -> Environment:
    """Build the case's environment exactly like the regression test does."""
    document: dict[str, Any] = {
        "schema_version": "1.0",
        "metadata": {"name": case["id"], "synthetic": True},
        "account_id": "111111111111",
        "coverage": {"services": {"iam": "complete", "s3": "complete", "lambda": "complete"}},
        "users": [],
        "groups": [],
        "roles": [],
        "managed_policies": [],
        "s3_buckets": [],
        "lambda_functions": [],
        "external_principals": [],
    }
    document.update(copy.deepcopy(case["environment"]))
    return parse_environment(document, case["id"])


def resource_policy_for(case: dict[str, Any], env: Environment) -> tuple[Any, str | None]:
    """Return ``(policy_document, owner_account)`` for the case's bucket policy, if any."""
    bucket_name = case.get("resource_policy_of")
    if bucket_name is None:
        return None, None
    bucket = env.bucket(f"arn:aws:s3:::{bucket_name}")
    if bucket is None or bucket.bucket_policy is None:
        raise CorpusError(f"{case['id']}: bucket {bucket_name} has no policy in the environment")
    return bucket.bucket_policy, bucket.account_id


def evaluate_locally(case: dict[str, Any], env: Environment, principal: Principal) -> str:
    """This project's decision for the case, in the corpus vocabulary."""
    request = case["request"]
    policy, owner = resource_policy_for(case, env)
    result = PolicyEvaluator(env).evaluate(
        principal,
        request["action"],
        request["resource"],
        resource_policy=policy,
        resource_account=owner,
        extra_context=request.get("context"),
    )
    return EVALUATOR_TO_CORPUS[result.decision]


# ---------------------------------------------------------------------------
# simulation request
# ---------------------------------------------------------------------------


def infer_context_type(key: str, values: list[str], multi_valued: bool) -> str:
    """Map a corpus context value onto a simulator ContextKeyType."""
    lowered = key.lower()
    base = _KEY_TYPES.get(lowered)
    if base is None and lowered.startswith(_STRING_KEY_PREFIXES):
        base = "string"
    if base is None:
        base = _type_of_value(values[0]) if values else "string"
    return f"{base}List" if multi_valued else base


def _type_of_value(value: str) -> str:
    text = value.strip()
    if text.lower() in {"true", "false"}:
        return "boolean"
    if _NUMERIC_RE.fullmatch(text):
        return "numeric"
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        pass
    else:
        return "ip"
    if _DATE_RE.fullmatch(text):
        return "date"
    return "string"


def context_entries(
    request_context: dict[str, Any], principal: Principal, policy_texts: list[str]
) -> list[dict[str, Any]]:
    """Build ContextEntries from the request context plus the principal facts the policies use.

    A ``null`` corpus value means "the key is absent from the request": no entry is sent, which
    is how the simulator models an absent key. SimulateCustomPolicy has no real caller, so the
    keys the project derives statically from the principal (aws:PrincipalArn,
    aws:PrincipalAccount, aws:username, aws:PrincipalTag/*) are supplied whenever a policy in
    the case references them, unless the request context already sets them.
    """
    entries: list[dict[str, Any]] = []
    supplied: set[str] = set()
    for key, value in request_context.items():
        if value is None:
            supplied.add(key.lower())
            continue
        values = list(value) if isinstance(value, list) else [str(value)]
        entries.append(_entry(key, values, isinstance(value, list)))
        supplied.add(key.lower())

    referenced = {m.lower() for text in policy_texts for m in _CONDITION_KEY_RE.findall(text)}
    facts: dict[str, str] = {
        "aws:PrincipalArn": principal.arn,
        "aws:PrincipalAccount": principal.account_id,
    }
    if isinstance(principal, User):
        facts["aws:username"] = principal.name
    for tag_key, tag_value in principal.tags.items():
        facts[f"aws:PrincipalTag/{tag_key}"] = tag_value
    for key, value in facts.items():
        if key.lower() in referenced and key.lower() not in supplied:
            entries.append(_entry(key, [value], False))
    return entries


def _entry(key: str, values: list[str], multi_valued: bool) -> dict[str, Any]:
    return {
        "ContextKeyName": key,
        "ContextKeyValues": values,
        "ContextKeyType": infer_context_type(key, values, multi_valued),
    }


def simulation_request(
    case: dict[str, Any], env: Environment, principal: Principal
) -> dict[str, Any]:
    """Translate one corpus case into ``simulate_custom_policy`` keyword arguments.

    Simulator limits that shape this translation:

    * Group membership does not exist in the simulator, so the user's inline and attached
      policies and those of its groups are all passed in ``PolicyInputList`` (the same set the
      offline evaluator resolves). A principal without any identity policy gets the
      no-permissions placeholder because ``PolicyInputList`` must not be empty.
    * Only one permissions boundary and one resource-based policy can be simulated.
    * ``CallerArn`` is required with a resource policy so that its Principal element can be
      matched; it must be an IAM user (resource-policy simulation is not supported for roles).
    * ``ResourceOwner`` names the account that owns the bucket; without it a cross-account case
      would be simulated as same-account.
    * The simulator has no "indeterminate" outcome and no snapshot: every condition key that a
      policy references must be supplied, otherwise it is treated as absent and reported under
      ``MissingContextValues``.
    """
    request = case["request"]
    evaluator = PolicyEvaluator(env)
    identity_docs = [doc.raw for doc in evaluator.identity_policies(principal)]
    unresolved = evaluator.unresolved_policies_for(principal)
    if unresolved:
        raise CorpusError(
            f"{case['id']}: attached policies missing from the environment: {unresolved}"
        )
    boundary_doc, unresolved_boundary = evaluator.boundary_policy(principal)
    if unresolved_boundary is not None:
        raise CorpusError(f"{case['id']}: permissions boundary {unresolved_boundary} is missing")
    resource_policy, owner = resource_policy_for(case, env)
    if request["resource"] == PLACEHOLDER_RESOURCE:
        raise CorpusError(f"{case['id']}: the placeholder resource must not be simulated")

    params: dict[str, Any] = {
        "PolicyInputList": [json.dumps(doc) for doc in identity_docs or [NO_PERMISSIONS_POLICY]],
        "ActionNames": [request["action"]],
        "ResourceArns": [request["resource"]],
    }
    policy_texts = list(params["PolicyInputList"])
    if boundary_doc is not None:
        params["PermissionsBoundaryPolicyInputList"] = [json.dumps(boundary_doc.raw)]
        policy_texts.extend(params["PermissionsBoundaryPolicyInputList"])
    if resource_policy is not None:
        params["ResourcePolicy"] = json.dumps(resource_policy.raw)
        params["CallerArn"] = principal.arn
        params["ResourceOwner"] = f"arn:aws:iam::{owner}:root"
        policy_texts.append(params["ResourcePolicy"])
    entries = context_entries(request.get("context") or {}, principal, policy_texts)
    if entries:
        params["ContextEntries"] = entries
    return params


def simulate(iam_client: Any, params: dict[str, Any]) -> tuple[str, list[str]]:
    """Call SimulateCustomPolicy and return ``(decision, missing_context_keys)``."""
    response = iam_client.simulate_custom_policy(**params)
    results = response.get("EvaluationResults") or []
    if len(results) != 1:
        raise RuntimeError(f"expected one evaluation result, got {len(results)}")
    result = results[0]
    missing: list[str] = [str(key) for key in result.get("MissingContextValues") or []]
    for specific in result.get("ResourceSpecificResults") or []:
        missing.extend(str(key) for key in specific.get("MissingContextValues") or [])
    decision = str(result["EvalDecision"])
    return SIMULATOR_TO_CORPUS.get(decision, decision), sorted(set(missing))


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


def build_session(profile: str, region: str) -> Any:
    """Create a boto3 session with the API guard installed, or ``None`` without boto3."""
    try:
        import boto3
    except ImportError:
        print(
            "boto3 is not installed; install the optional AWS dependencies with "
            "`pip install -e '.[aws]'` and re-run.",
            file=sys.stderr,
        )
        return None
    session = boto3.session.Session(profile_name=profile, region_name=region)
    install_guard(session)
    return session


def print_plan(args: argparse.Namespace, cases: list[dict[str, Any]]) -> None:
    supported = [case for case in cases if case["simulator"]["supported"]]
    skipped = [case for case in cases if not case["simulator"]["supported"]]
    print("IAM policy simulator validation plan (no AWS call has been made)")
    print(f"  corpus:         {args.cases} ({len(cases)} cases)")
    print(f"  to simulate:    {len(supported)} cases with simulator.supported = true")
    print(f"  skipped:        {len(skipped)} cases with simulator.supported = false")
    print(f"  profile/region: {args.profile} / {args.region}")
    print("  API operations: " + ", ".join(API_OPERATIONS))
    print(
        "                  (GetCallerIdentity once, SimulateCustomPolicy once per simulated case)"
    )
    if args.output:
        print(f"  results file:   {args.output} (mode 0600)")
    print("Re-run with --confirm to execute the plan.")


def format_table(results: list[CaseResult]) -> str:
    rows = [("case id", "expected", "simulator", "evaluator", "match")]
    rows.extend((r.case_id, r.expected, r.simulator, r.evaluator, r.match) for r in results)
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def classify(expected: str, simulator: str, evaluator: str) -> str:
    if simulator == expected and evaluator == expected:
        return "yes"
    if simulator != expected and evaluator != expected:
        return "no (simulator and evaluator differ from expected)"
    if simulator != expected:
        return "no (simulator differs from expected)"
    return "no (evaluator differs from expected)"


def run_case(case: dict[str, Any], iam_client: Any) -> CaseResult:
    env = build_environment(case)
    principal = env.principal(case["request"]["principal"])
    if principal is None:
        raise CorpusError(f"{case['id']}: principal is not in the environment")
    evaluator_decision = evaluate_locally(case, env, principal)
    params = simulation_request(case, env, principal)
    error: str | None = None
    missing: list[str] = []
    try:
        simulator_decision, missing = simulate(iam_client, params)
    except ApiGuardError:
        raise
    except Exception as exc:  # the simulator rejected the input; report it, keep going
        simulator_decision = "error"
        error = f"{type(exc).__name__}: {exc}"
    return CaseResult(
        case_id=case["id"],
        area=case["area"],
        status=case["status"],
        expected=case["expected"],
        simulator=simulator_decision,
        evaluator=evaluator_decision,
        match=classify(case["expected"], simulator_decision, evaluator_decision),
        missing_context=missing,
        error=error,
    )


def write_results(path: Path, payload: dict[str, Any]) -> None:
    """Write ``payload`` as JSON readable only by the current user."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    path.chmod(0o600)  # O_CREAT mode only applies to newly created files


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate tests/regression/iam_cases.json against the IAM policy simulator.",
        epilog="Without --confirm the script prints its plan and exits with status 1.",
    )
    parser.add_argument("--profile", required=True, help="AWS CLI profile to use")
    parser.add_argument(
        "--region", default=DEFAULT_REGION, help=f"region (default {DEFAULT_REGION})"
    )
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES, help="corpus path")
    parser.add_argument("--confirm", action="store_true", help="actually call the simulator")
    parser.add_argument("--output", type=Path, default=None, help="write JSON results here")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        cases = load_cases(args.cases)
    except CorpusError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not args.confirm:
        print_plan(args, cases)
        return 1

    session = build_session(args.profile, args.region)
    if session is None:
        return 2
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    caller_arn = str(identity.get("Arn", ""))
    if caller_arn.endswith(":root"):
        print(
            "refusing to run with AWS account root credentials; use an IAM user or role",
            file=sys.stderr,
        )
        return 2
    print(f"caller: {caller_arn}")

    iam = session.client("iam")
    results: list[CaseResult] = []
    skipped: list[dict[str, Any]] = []
    for case in cases:
        if not case["simulator"]["supported"]:
            skipped.append(case)
            continue
        try:
            results.append(run_case(case, iam))
        except CorpusError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    print(format_table(results))
    for result in results:
        if result.missing_context:
            print(f"  {result.case_id}: missing context values {result.missing_context}")
        if result.error:
            print(f"  {result.case_id}: {result.error}")
    if skipped:
        print("\nskipped (simulator.supported = false):")
        for case in skipped:
            print(f"  {case['id']}: {case['simulator'].get('note', '')}")

    agreeing = sum(1 for r in results if r.match == "yes")
    print(f"\n{agreeing}/{len(results)} simulated cases agree with the documented expectation")

    if args.output is not None:
        payload = {
            "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "corpus": str(args.cases),
            "region": args.region,
            "caller_arn": caller_arn,
            "results": [asdict(r) for r in results],
            "skipped": [case["id"] for case in skipped],
        }
        write_results(args.output, payload)
        print(f"results written to {args.output}")

    return 0 if results and agreeing == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
