# Incident scenarios

Each scenario below is a synthetic fixture under `fixtures/scenarios/` (derived from `fixtures/sample_environment.json` by `scripts/build_scenarios.py`). The **expected result** is the expectation recorded in `src/attackpath/data/scenarios/expected.json`; the **actual result** is produced by running the analyzer while generating this page (`scripts/generate_scenario_docs.py`), so the two cannot drift silently. `python -m attackpath validate` runs the same comparison.

All identities, account ids and resources are fictional.

## 01-overly-broad-role

A role with Action * on Resource * is reported as administrative.

**Initial configuration.** Role `ops-admin-legacy` carries an inline policy with `Action: *` on `Resource: *`. Its trust policy admits the whole account (`arn:aws:iam::111111111111:root`) and the EC2 service.

**Expected result.**

- present: ADMIN principal~role/ops-admin-legacy >=high evidence=observed
- absent: WILDCARD principal~role/ops-admin-legacy (administrative access already implies the wildcard grant)

**Actual result.** 1 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| critical | `ADMIN` | observed | Role ops-admin-legacy has administrative permissions |

**Why the result is correct.** The administrative probe asks the evaluator for eight high-impact actions on `*` (IAM user and policy management, `sts:AssumeRole`, S3, EC2, Lambda, KMS). All are allowed with no Deny and no boundary, so the role is administrative by configuration, not by heuristic. The wildcard check is suppressed for administrative principals because it would restate the same fact.

**Limitations.** Service control policies are outside the snapshot; an SCP could restrict this role without the analyzer seeing it (recorded in docs/limitations.md).

## 02-risky-trust

Anonymous trust, cross-account trust without ExternalId, and cross-account trust with ExternalId.

**Initial configuration.** Three roles: `vendor-support-access` trusts `Principal: "*"` with no condition and holds `AmazonS3FullAccess`; `partner-integration` trusts account `222222222222` (declared as a known partner) without an `sts:ExternalId`; `third-party-monitoring` trusts account `333333333333` with an `sts:ExternalId` condition.

**Expected result.**

- present: TRUST-ANONYMOUS principal~role/vendor-support-access >=critical evidence=observed
- present: TRUST-CROSS-ACCOUNT principal~role/partner-integration tag=missing-external-id
- present: TRUST-CROSS-ACCOUNT principal~role/third-party-monitoring <=medium tag=external-id-required
- present: PATH-SENSITIVE resource~customer-pii-exports >=high (any AWS principal -> vendor-support-access -> PII bucket)
- present: EVAL-INDETERMINATE resource~third-party-monitoring (the sts:ExternalId condition value is request-time context)

**Actual result.** 11 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| critical | `TRUST-ANONYMOUS` | observed | Role vendor-support-access can be assumed by any AWS principal |
| high | `SENSITIVE-ACCESS` | observed | Role vendor-support-access can delete/list/policy/read/write sensitive bucket customer-pii-exports |
| high | `PATH-SENSITIVE` | inferred | Any AWS principal / anonymous can reach bucket customer-pii-exports in 2 step(s) |
| high | `SENSITIVE-ACCESS` | observed | Role vendor-support-access can delete/list/policy/read/write sensitive bucket finance-reports |
| high | `PATH-SENSITIVE` | inferred | Any AWS principal / anonymous can reach bucket finance-reports in 2 step(s) |
| high | `WILDCARD` | observed | Role vendor-support-access is granted s3:*, s3-object-lambda:* on * |
| medium | `TRUST-CROSS-ACCOUNT` | observed | Role partner-integration trusts account arn:aws:iam::222222222222:root without an sts:ExternalId condition |
| medium | `SENSITIVE-ACCESS` | observed | Role partner-integration can list/read sensitive bucket finance-reports |
| low | `TRUST-CROSS-ACCOUNT` | observed | Role third-party-monitoring trusts account arn:aws:iam::333333333333:root (sts:ExternalId required) |
| low | `PATH-SENSITIVE` | hypothetical | Account 222222222222 can reach bucket finance-reports in 2 step(s) |
| informational | `EVAL-INDETERMINATE` | indeterminate | Statement could not be fully evaluated: trust:arn:aws:iam::111111111111:role/third-party-monitoring statement[0] |

**Why the result is correct.** A wildcard principal without conditions means any AWS account can call `sts:AssumeRole`; combined with S3 full access it yields a two-step path from outside the account to the PII bucket. Cross-account trust is reported as an observed configuration fact; the ability of the other account to use it is a precondition because that account's identity policies are not in the snapshot. The ExternalId condition cannot be evaluated offline, so it becomes a stated precondition and an evaluation-limitation finding rather than a guess.

**Limitations.** The analyzer cannot know whether `222222222222` is well governed; the `known` flag only adjusts the exposure factor.

## 03-passrole-broad

A deployment user holds iam:PassRole on * together with Lambda write permissions.

**Initial configuration.** User `ci-deployer` has `iam:PassRole` on `*` without an `iam:PassedToService` condition, plus `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration` and `lambda:InvokeFunction` on `*`. The account contains a service-trusted administrative role.

**Expected result.**

- present: PASSROLE-BROAD principal~user/ci-deployer >=high evidence=observed
- present: LAMBDA-WRITE principal~user/ci-deployer >=medium
- absent: ADMIN principal~user/ci-deployer

**Actual result.** 5 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| critical | `ADMIN` | observed | Role ops-admin-legacy has administrative permissions |
| high | `PASSROLE-BROAD` | observed | User ci-deployer may pass any role to AWS services |
| high | `LAMBDA-WRITE` | observed | User ci-deployer may change the code or configuration of any Lambda function |
| high | `SENSITIVE-ACCESS` | observed | Workload role lambda-image-resizer can delete/list/policy/read/write sensitive bucket customer-pii-exports |
| medium | `WILDCARD` | observed | Role lambda-image-resizer is granted s3:*, s3-object-lambda:* on * |

**Why the result is correct.** The finding is a configuration finding: the broad `iam:PassRole` grant is observed, and the paired service permissions and service-trusted roles in the snapshot are listed as context that raises the escalation factor. The analyzer does not simulate the resulting workflow; it reports the grant and the least-privilege fix (specific role ARN plus `iam:PassedToService`).

**Limitations.** Whether a deployment pipeline would actually accept an arbitrary role depends on controls outside IAM (code review, CI configuration) that the snapshot does not describe.

## 04-workload-s3-access

A function's execution role has S3 full access and therefore reaches a high-sensitivity bucket.

**Initial configuration.** Function `image-resizer` runs under role `lambda-image-resizer`, which has `AmazonS3FullAccess`. The account has a high-sensitivity bucket `customer-pii-exports` the function has no business with.

**Expected result.**

- present: SENSITIVE-ACCESS principal~role/lambda-image-resizer resource~customer-pii-exports >=high tag=workload
- present: WILDCARD principal~role/lambda-image-resizer
- absent: PATH-SENSITIVE (function -> own role -> bucket is the same fact as the workload finding)

**Actual result.** 2 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| high | `SENSITIVE-ACCESS` | observed | Workload role lambda-image-resizer can delete/list/policy/read/write sensitive bucket customer-pii-exports |
| medium | `WILDCARD` | observed | Role lambda-image-resizer is granted s3:*, s3-object-lambda:* on * |

**Why the result is correct.** The sensitive-access check evaluates read, list, write, delete and bucket-policy actions for the role against the bucket (identity policy plus bucket policy plus Block Public Access) and finds all of them allowed. Because the role is service-trusted and used by a function, the finding is tagged `workload`: the data is only as safe as the code running under that role. The function -> role -> bucket path is deliberately not reported a second time as a reachability path.

**Limitations.** Sensitivity comes from the snapshot's declared `sensitivity` field (or tags); the analyzer does not classify data.

## 05-public-bucket

Public bucket policies: effective, mitigated by Block Public Access, and intentionally public low-sensitivity data.

**Initial configuration.** `legacy-backups` (high sensitivity) has a bucket policy granting `s3:GetObject` to `*` and no Block Public Access configuration; `archive-with-restricted-policy` has the same statement but `RestrictPublicBuckets` enabled; `public-marketing-assets` is a declared low-sensitivity bucket that is intentionally public.

**Expected result.**

- present: S3-PUBLIC-POLICY resource~legacy-backups >=high evidence=observed
- present: S3-PUBLIC-POLICY resource~archive-with-restricted-policy <=low tag=mitigated-by-block-public-access
- present: S3-PUBLIC-POLICY resource~public-marketing-assets <=medium

**Actual result.** 3 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| high | `S3-PUBLIC-POLICY` | observed | Bucket legacy-backups is publicly accessible through its bucket policy |
| medium | `S3-PUBLIC-POLICY` | observed | Bucket public-marketing-assets is publicly accessible through its bucket policy |
| low | `S3-PUBLIC-POLICY` | observed | Bucket archive-with-restricted-policy has a public bucket policy (blocked by Block Public Access) |

**Why the result is correct.** The anonymous identity is evaluated against each bucket policy. For the first bucket the grant is effective and the data sensitive, so the finding is high. For the second, `RestrictPublicBuckets` makes the public statement inert, which the finding states in its title and reflects in lower trust-boundary, exposure and reachability factors. For the third, the low declared sensitivity keeps the score at medium: public buckets always deserve a review, but the data is not sensitive.

**Limitations.** Account-level Block Public Access settings are not part of the snapshot schema yet.

## 06-explicit-deny

A group grants s3:GetObject on * but an inline Deny blocks the PII bucket; the deny must win.

**Initial configuration.** User `analyst-readonly` inherits `s3:GetObject`/`s3:ListBucket` on `*` from the `data-analysts` group but carries an inline Deny for the PII bucket and for `s3:DeleteObject`/`s3:PutBucketPolicy` everywhere.

**Expected result.**

- absent: SENSITIVE-ACCESS principal~user/analyst-readonly resource~customer-pii-exports (explicit Deny on the PII bucket)
- present: SENSITIVE-ACCESS principal~user/analyst-readonly resource~finance-reports <=medium
- absent: * >=high

**Actual result.** 1 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| low | `SENSITIVE-ACCESS` | observed | User analyst-readonly can list/read sensitive bucket finance-reports |

**Why the result is correct.** Explicit Deny always wins in the evaluator, so the PII bucket produces no access edge and no finding for this user, while `finance-reports` (medium sensitivity) is reported as read/list access. The finding records the denied classes (`delete`, `policy`) as evidence that the Deny was honoured.

**Limitations.** None specific to this scenario.

## 07-unknown-condition

An Allow guarded by aws:SourceVpce cannot be decided offline and is reported as indeterminate.

**Initial configuration.** Role `finance-reporting` may read `customer-pii-exports/*` only when `aws:SourceVpce` equals a specific VPC endpoint id.

**Expected result.**

- present: SENSITIVE-ACCESS principal~role/finance-reporting resource~customer-pii-exports <=medium evidence=indeterminate
- present: EVAL-INDETERMINATE resource~role/finance-reporting
- absent: SENSITIVE-ACCESS principal~role/finance-reporting evidence=observed

**Actual result.** 2 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| informational | `SENSITIVE-ACCESS` | indeterminate | Role finance-reporting can read sensitive bucket customer-pii-exports |
| informational | `EVAL-INDETERMINATE` | indeterminate | Statement could not be fully evaluated: inline:arn:aws:iam::111111111111:role/finance-reporting:vpce-only statement[0] (Sid: ReadExportsViaEndpoint) |

**Why the result is correct.** `aws:SourceVpce` is request-time context that a configuration snapshot does not contain. The condition evaluates to UNKNOWN, the access decision is `indeterminate`, and the finding says so with low confidence and a capped severity. A separate evaluation-limitation finding points at the statement. Treating the condition as satisfied would overstate the risk; treating it as unsatisfied would hide it.

**Limitations.** Supplying the real context values (for example through the policy simulator) is the only way to resolve it.

## 08-safe-configuration

A least-privilege execution role scoped to its two buckets produces no high-severity finding.

**Initial configuration.** Role `lambda-thumbnailer-least-priv` can `s3:GetObject` on `thumbnail-input/*` and `s3:PutObject` on `thumbnail-output/*`, writes logs, and is trusted only by the Lambda service. Coverage is complete.

**Expected result.**

- absent: * >=medium
- absent: SENSITIVE-ACCESS
- absent: WILDCARD
- absent: ADMIN
- absent: COVERAGE-PARTIAL

**Actual result.** 0 finding(s); all expectations met.

**Why the result is correct.** No statement is broad, both buckets are low sensitivity, no trust crosses the account boundary and the inventory is complete, so the analyzer produces nothing at medium or above. A tool that flagged this configuration would be training its users to ignore it.

**Limitations.** None.

## 09-incomplete-inventory

Unresolved managed policy, missing execution role and partial Lambda coverage produce coverage warnings.

**Initial configuration.** Role `data-pipeline-worker` references managed policy `pipeline-unresolved`, whose document is absent from the snapshot; function `orphan-cleanup` uses a role that is not in the snapshot; Lambda coverage is declared partial for one region.

**Expected result.**

- present: COVERAGE-PARTIAL resource~lambda
- present: COVERAGE-UNRESOLVED-POLICY resource~pipeline-unresolved
- present: COVERAGE-UNRESOLVED-ROLE resource~cleanup-role-missing
- absent: ADMIN principal~role/data-pipeline-worker (a missing document alone must not produce a privilege finding)

**Actual result.** 3 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| low | `COVERAGE-UNRESOLVED-POLICY` | observed | Policy document arn:aws:iam::111111111111:policy/pipeline-unresolved is referenced but not present in the snapshot |
| low | `COVERAGE-UNRESOLVED-ROLE` | observed | Execution role arn:aws:iam::111111111111:role/cleanup-role-missing is used by functions but not present in the snapshot |
| informational | `COVERAGE-PARTIAL` | observed | Inventory coverage for lambda is partial |

**Why the result is correct.** Each gap becomes a coverage finding so that the absence of other findings is not mistaken for safety. The missing document alone does not produce a privilege finding for the role: the evaluator records it as a limitation and marks dependent decisions indeterminate instead of inventing a result.

**Limitations.** The analyzer can only report gaps the snapshot declares or that it can infer from dangling references.

## 10-remediation-before

A user with sts:AssumeRole on * reaches an administrative role trusted by the whole account.

**Initial configuration.** User `legacy-automation` (long-lived access key, no MFA) has `sts:AssumeRole` on `*`; role `ops-admin-legacy` is administrative and trusts the whole account.

**Expected result.**

- present: PATH-ADMIN principal~user/legacy-automation resource~role/ops-admin-legacy >=critical evidence=observed
- present: ASSUME-BROAD principal~user/legacy-automation >=high

**Actual result.** 3 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| critical | `PATH-ADMIN` | observed | User legacy-automation can reach role ops-admin-legacy in 1 step(s) |
| critical | `ADMIN` | observed | Role ops-admin-legacy has administrative permissions |
| high | `ASSUME-BROAD` | observed | User legacy-automation may assume any role matching a broad pattern |

**Why the result is correct.** Account-root trust requires an identity-policy `sts:AssumeRole` allow, which the user has for any role, so a one-step path to administrative permissions exists and is reported as critical, alongside the broad `sts:AssumeRole` grant itself.

**Limitations.** None.

## 10-remediation-after

The same environment after scoping sts:AssumeRole and narrowing the trust policy: the path is gone.

**Initial configuration.** The remediation from the previous finding is applied: the user's `sts:AssumeRole` is scoped to the pipeline role only, and `ops-admin-legacy` now trusts a single MFA-protected break-glass user.

**Expected result.**

- absent: PATH-ADMIN principal~user/legacy-automation
- absent: ASSUME-BROAD principal~user/legacy-automation
- present: ADMIN principal~role/ops-admin-legacy (the role itself is still administrative; only the path to it was removed)
- absent: PATH-ADMIN

**Actual result.** 3 finding(s); all expectations met.

| Severity | Check | Evidence | Title |
|---|---|---|---|
| high | `ADMIN` | observed | User break-glass-admin has administrative permissions |
| high | `ADMIN` | observed | Role ops-admin-legacy has administrative permissions |
| informational | `EVAL-INDETERMINATE` | indeterminate | Statement could not be fully evaluated: trust:arn:aws:iam::111111111111:role/ops-admin-legacy statement[0] |

**Why the result is correct.** The user can no longer satisfy either half of the assume-role check, so the path and the broad-grant finding disappear, while the role itself is still (correctly) reported as administrative. This is the verification step every path finding recommends: re-run on the changed configuration and confirm the finding id is gone.

**Limitations.** None.

## Summary

11 scenarios, 37 expectation(s) met, 0 failed at the time this page was generated.
