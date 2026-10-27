#!/usr/bin/env python3
"""Generate docs/incident-scenarios.md from the bundled scenarios and their live results.

The narrative for each scenario (initial configuration, why the expected result is correct,
limitations) is written by hand below. The "expected result" and "actual result" sections are
produced by running the analyzer, so the document can never claim an outcome the code does not
deliver. Run after any change to the checks or fixtures:  python scripts/generate_scenario_docs.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attackpath import selfcheck  # noqa: E402
from attackpath.analysis.engine import analyze  # noqa: E402
from attackpath.parser.environment_parser import parse_environment  # noqa: E402

OUTPUT = ROOT / "docs" / "incident-scenarios.md"

NARRATIVE: dict[str, dict[str, str]] = {
    "01-overly-broad-role": {
        "configuration": (
            "Role `ops-admin-legacy` carries an inline policy with `Action: *` on `Resource: *`. Its trust "
            "policy admits the whole account (`arn:aws:iam::111111111111:root`) and the EC2 service."
        ),
        "why": (
            "The administrative probe asks the evaluator for eight high-impact actions on `*` (IAM user and "
            "policy management, `sts:AssumeRole`, S3, EC2, Lambda, KMS). All are allowed with no Deny and no "
            "boundary, so the role is administrative by configuration, not by heuristic. The wildcard check is "
            "suppressed for administrative principals because it would restate the same fact."
        ),
        "limitations": (
            "Service control policies are outside the snapshot; an SCP could restrict this role without the "
            "analyzer seeing it (recorded in docs/limitations.md)."
        ),
    },
    "02-risky-trust": {
        "configuration": (
            'Three roles: `vendor-support-access` trusts `Principal: "*"` with no condition and holds '
            "`AmazonS3FullAccess`; `partner-integration` trusts account `222222222222` (declared as a known "
            "partner) without an `sts:ExternalId`; `third-party-monitoring` trusts account `333333333333` with "
            "an `sts:ExternalId` condition."
        ),
        "why": (
            "A wildcard principal without conditions means any AWS account can call `sts:AssumeRole`; combined "
            "with S3 full access it yields a two-step path from outside the account to the PII bucket. "
            "Cross-account trust is reported as an observed configuration fact; the ability of the other account "
            "to use it is a precondition because that account's identity policies are not in the snapshot. "
            "The ExternalId condition cannot be evaluated offline, so it becomes a stated precondition and an "
            "evaluation-limitation finding rather than a guess."
        ),
        "limitations": (
            "The analyzer cannot know whether `222222222222` is well governed; the `known` flag only adjusts "
            "the exposure factor."
        ),
    },
    "03-passrole-broad": {
        "configuration": (
            "User `ci-deployer` has `iam:PassRole` on `*` without an `iam:PassedToService` condition, plus "
            "`lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration` and "
            "`lambda:InvokeFunction` on `*`. The account contains a service-trusted administrative role."
        ),
        "why": (
            "The finding is a configuration finding: the broad `iam:PassRole` grant is observed, and the paired "
            "service permissions and service-trusted roles in the snapshot are listed as context that raises "
            "the escalation factor. The analyzer does not simulate the resulting workflow; it reports the grant "
            "and the least-privilege fix (specific role ARN plus `iam:PassedToService`)."
        ),
        "limitations": (
            "Whether a deployment pipeline would actually accept an arbitrary role depends on controls outside "
            "IAM (code review, CI configuration) that the snapshot does not describe."
        ),
    },
    "04-workload-s3-access": {
        "configuration": (
            "Function `image-resizer` runs under role `lambda-image-resizer`, which has `AmazonS3FullAccess`. "
            "The account has a high-sensitivity bucket `customer-pii-exports` the function has no business with."
        ),
        "why": (
            "The sensitive-access check evaluates read, list, write, delete and bucket-policy actions for the role "
            "against the bucket (identity policy plus bucket policy plus Block Public Access) and finds all of them "
            "allowed. Because the role is service-trusted and used by a function, the finding is tagged `workload`: "
            "the data is only as safe as the code running under that role. The function -> role -> bucket path is "
            "deliberately not reported a second time as a reachability path."
        ),
        "limitations": "Sensitivity comes from the snapshot's declared `sensitivity` field (or tags); the analyzer does not classify data.",
    },
    "05-public-bucket": {
        "configuration": (
            "`legacy-backups` (high sensitivity) has a bucket policy granting `s3:GetObject` to `*` and no Block "
            "Public Access configuration; `archive-with-restricted-policy` has the same statement but "
            "`RestrictPublicBuckets` enabled; `public-marketing-assets` is a declared low-sensitivity bucket that "
            "is intentionally public."
        ),
        "why": (
            "The anonymous identity is evaluated against each bucket policy. For the first bucket the grant is "
            "effective and the data sensitive, so the finding is high. For the second, `RestrictPublicBuckets` "
            "makes the public statement inert, which the finding states in its title and reflects in lower "
            "trust-boundary, exposure and reachability factors. For the third, the low declared sensitivity keeps "
            "the score at medium: public buckets always deserve a review, but the data is not sensitive."
        ),
        "limitations": "Account-level Block Public Access settings are not part of the snapshot schema yet.",
    },
    "06-explicit-deny": {
        "configuration": (
            "User `analyst-readonly` inherits `s3:GetObject`/`s3:ListBucket` on `*` from the `data-analysts` group "
            "but carries an inline Deny for the PII bucket and for `s3:DeleteObject`/`s3:PutBucketPolicy` everywhere."
        ),
        "why": (
            "Explicit Deny always wins in the evaluator, so the PII bucket produces no access edge and no finding for "
            "this user, while `finance-reports` (medium sensitivity) is reported as read/list access. The finding "
            "records the denied classes (`delete`, `policy`) as evidence that the Deny was honoured."
        ),
        "limitations": "None specific to this scenario.",
    },
    "07-unknown-condition": {
        "configuration": (
            "Role `finance-reporting` may read `customer-pii-exports/*` only when `aws:SourceVpce` equals a specific "
            "VPC endpoint id."
        ),
        "why": (
            "`aws:SourceVpce` is request-time context that a configuration snapshot does not contain. The condition "
            "evaluates to UNKNOWN, the access decision is `indeterminate`, and the finding says so with low "
            "confidence and a capped severity. A separate evaluation-limitation finding points at the statement. "
            "Treating the condition as satisfied would overstate the risk; treating it as unsatisfied would hide it."
        ),
        "limitations": "Supplying the real context values (for example through the policy simulator) is the only way to resolve it.",
    },
    "08-safe-configuration": {
        "configuration": (
            "Role `lambda-thumbnailer-least-priv` can `s3:GetObject` on `thumbnail-input/*` and `s3:PutObject` on "
            "`thumbnail-output/*`, writes logs, and is trusted only by the Lambda service. Coverage is complete."
        ),
        "why": (
            "No statement is broad, both buckets are low sensitivity, no trust crosses the account boundary and the "
            "inventory is complete, so the analyzer produces nothing at medium or above. A tool that flagged this "
            "configuration would be training its users to ignore it."
        ),
        "limitations": "None.",
    },
    "09-incomplete-inventory": {
        "configuration": (
            "Role `data-pipeline-worker` references managed policy `pipeline-unresolved`, whose document is absent "
            "from the snapshot; function `orphan-cleanup` uses a role that is not in the snapshot; Lambda coverage "
            "is declared partial for one region."
        ),
        "why": (
            "Each gap becomes a coverage finding so that the absence of other findings is not mistaken for safety. "
            "The missing document alone does not produce a privilege finding for the role: the evaluator records "
            "it as a limitation and marks dependent decisions indeterminate instead of inventing a result."
        ),
        "limitations": "The analyzer can only report gaps the snapshot declares or that it can infer from dangling references.",
    },
    "10-remediation-before": {
        "configuration": (
            "User `legacy-automation` (long-lived access key, no MFA) has `sts:AssumeRole` on `*`; role "
            "`ops-admin-legacy` is administrative and trusts the whole account."
        ),
        "why": (
            "Account-root trust requires an identity-policy `sts:AssumeRole` allow, which the user has for any role, "
            "so a one-step path to administrative permissions exists and is reported as critical, alongside the "
            "broad `sts:AssumeRole` grant itself."
        ),
        "limitations": "None.",
    },
    "10-remediation-after": {
        "configuration": (
            "The remediation from the previous finding is applied: the user's `sts:AssumeRole` is scoped to the "
            "pipeline role only, and `ops-admin-legacy` now trusts a single MFA-protected break-glass user."
        ),
        "why": (
            "The user can no longer satisfy either half of the assume-role check, so the path and the broad-grant "
            "finding disappear, while the role itself is still (correctly) reported as administrative. This is the "
            "verification step every path finding recommends: re-run on the changed configuration and confirm the "
            "finding id is gone."
        ),
        "limitations": "None.",
    },
}


def main() -> int:
    scenarios = selfcheck.load_scenarios()
    lines: list[str] = []
    lines.append("# Incident scenarios")
    lines.append("")
    lines.append(
        "Each scenario below is a synthetic fixture under `fixtures/scenarios/` (derived from "
        "`fixtures/sample_environment.json` by `scripts/build_scenarios.py`). The **expected result** "
        "is the expectation recorded in `src/attackpath/data/scenarios/expected.json`; the **actual result** "
        "is produced by running the analyzer while generating this page (`scripts/generate_scenario_docs.py`), "
        "so the two cannot drift silently. `python -m attackpath validate` runs the same comparison."
    )
    lines.append("")
    lines.append("All identities, account ids and resources are fictional.")
    lines.append("")
    total_pass = total_fail = 0
    for scenario in scenarios:
        narrative = NARRATIVE.get(scenario.name, {})
        result = selfcheck.run_scenario(scenario)
        data = json.loads((selfcheck.scenario_dir() / scenario.fixture).read_text("utf-8"))
        analysis = analyze(parse_environment(data, scenario.fixture))
        total_pass += len(result.passed)
        total_fail += len(result.failed)
        lines.append(f"## {scenario.name}")
        lines.append("")
        lines.append(scenario.description)
        lines.append("")
        lines.append("**Initial configuration.** " + narrative.get("configuration", ""))
        lines.append("")
        lines.append("**Expected result.**")
        lines.append("")
        for expectation in scenario.expectations:
            note = f" ({expectation.note})" if expectation.note else ""
            lines.append(f"- {expectation.describe()}{note}")
        lines.append("")
        status = "all expectations met" if result.ok else "EXPECTATIONS NOT MET"
        lines.append(f"**Actual result.** {len(analysis.findings)} finding(s); {status}.")
        lines.append("")
        if analysis.findings:
            lines.append("| Severity | Check | Evidence | Title |")
            lines.append("|---|---|---|---|")
            for finding in analysis.findings:
                title = finding.title.replace("|", "\\|")
                lines.append(
                    f"| {finding.severity.value} | `{finding.check_id}` | {finding.evidence_kind.value} | {title} |"
                )
            lines.append("")
        for failure in result.failed:
            lines.append(f"- FAILED: {failure}")
        if result.failed:
            lines.append("")
        lines.append("**Why the result is correct.** " + narrative.get("why", ""))
        lines.append("")
        lines.append("**Limitations.** " + narrative.get("limitations", ""))
        lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"{len(scenarios)} scenarios, {total_pass} expectation(s) met, {total_fail} failed at the time this "
        "page was generated."
    )
    lines.append("")
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUTPUT} ({total_pass} met, {total_fail} failed)")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
