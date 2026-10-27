# IAM evaluation regression corpus

`tests/regression/iam_cases.json` is a corpus of IAM authorization questions whose expected
answers come from the AWS documentation, not from this project's evaluator. It exists so that
the evaluator is measured against an independent specification: a case that the evaluator gets
wrong is recorded as a *disputed* case with the documentation citation, and it stays visible in
the test suite until a maintainer decides whether the evaluator or the case is wrong.

The corpus currently holds 41 cases, all confirmed (the three that were disputed when the corpus
was first run led to evaluator fixes; see below), across eight areas:

| Area | Cases | What it covers |
| --- | --- | --- |
| `evaluation-order` | 3 | explicit deny over allow (identity vs identity, resource policy vs identity), implicit deny |
| `wildcards` | 5 | `s3:Get*`, `s3:*`, `*`, case-insensitive action names, `*`/`?` in resource ARNs |
| `not-elements` | 4 | `NotAction` and `NotResource`, each with `Allow` and with `Deny` |
| `boundary` | 3 | boundary intersection, explicit deny in the boundary, boundary alone grants nothing |
| `resource-policy` | 6 | same account: either side suffices when the principal is named directly, an account-root principal only delegates; cross account: both sides needed |
| `conditions` | 14 | string, numeric, date, boolean, IP, `Null`, `...IfExists`, `ForAllValues`/`ForAnyValue`, unknown request keys |
| `policy-variables` | 3 | `${aws:username}` and `${aws:PrincipalTag/...}` in `Resource`, the `Version` requirement |
| `principals` | 3 | `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:SourceAccount` |

## How the expectations were sourced

Every case cites one page of the IAM User Guide (or the IAM API Reference) and paraphrases, in
one sentence, the rule on that page that fixes the outcome. The expected decision was derived
from that sentence before the case was run against the evaluator; running the evaluator only
decided whether the case is `confirmed` (evaluator agrees) or `disputed` (evaluator disagrees).
No expectation was changed to make the evaluator pass. The pages used are:

* Policy evaluation logic, including *How AWS enforcement code logic evaluates requests* and the
  cross-account evaluation page (implicit deny, explicit deny, group policies, boundaries,
  resource-based policies for IAM users, cross-account "both sides" rule).
* JSON policy elements: `Action`, `Resource`, `NotAction`, `NotResource`, `Principal`.
* Permissions boundaries for IAM entities.
* Condition operators; single-valued vs. multivalued context keys (`ForAllValues`/`ForAnyValue`).
* Policy variables and tags.
* AWS global condition context keys (availability of each key in the request context).

Two conventions make absent and unknown keys explicit:

* A request context value of `null` means *the key is known to be absent* from the request
  (for example `aws:SourceAccount` for a request made directly by a user).
* A key that is missing from the request context is *unknown*. This project reports such a case
  as `indeterminate` rather than guessing; the corpus contains one such case
  (`unknown-request-key-is-indeterminate`), and the rule sentence records the two outcomes
  AWS would produce depending on the request-time value.

## Case schema

```jsonc
{
  "id": "deny-overrides-allow-identity",          // unique, kebab-case; used as the pytest id
  "title": "one line",
  "area": "evaluation-order",                     // one of the eight areas above
  "source": {
    "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/...",
    "rule": "one-sentence paraphrase of the documented rule that fixes the outcome"
  },
  "environment": { "users": [...], "groups": [...], "roles": [...],
                   "managed_policies": [...], "s3_buckets": [...] },   // snapshot fragment
  "request": {
    "principal": "arn:aws:iam::111111111111:user/alice",            // must exist in environment
    "action": "s3:GetObject",
    "resource": "arn:aws:s3:::data/report.csv",
    "context": { "aws:SourceIp": "203.0.113.7", "aws:TagKeys": ["env"], "aws:SourceVpce": null }
  },
  "resource_policy_of": "data",                   // optional: bucket whose policy is the resource policy
  "expected": "allowed",                          // allowed | explicit_deny | implicit_deny | indeterminate
  "status": "confirmed",                          // confirmed | disputed
  "note": "...",                                  // required for disputed cases: documented rule vs observed decision
  "simulator": { "supported": true, "note": "optional caveat; required when supported is false" }
}
```

The `environment` fragment uses the snapshot format described in `docs/input-format.md` and is
merged into a minimal valid snapshot for account `111111111111`; buckets in account
`222222222222` carry an explicit `account_id`. Only these two synthetic account ids may appear.

## How the test uses the corpus

`tests/regression/test_iam_cases.py`:

* builds each environment with `parse_environment`, looks up the principal, takes the bucket
  policy named by `resource_policy_of` (with the bucket's account as the resource account), and
  calls `PolicyEvaluator(env).evaluate(...)` with the request context as `extra_context`;
* parametrizes `test_documented_outcome` over all cases with the case id as the test id.
  Confirmed cases must produce the expected `Decision`. Disputed cases are collected with
  `pytest.mark.xfail(strict=True, reason=<note>)`: they are reported as `xfail` while the
  evaluator disagrees, and as a strict failure (`XPASS`) as soon as the evaluator starts to agree,
  which is the signal to flip the case to `confirmed`;
* checks corpus integrity: unique and well-formed ids, allowed values for `area`, `expected` and
  `status`, every source URL under `https://docs.aws.amazon.com/`, notes present where required,
  only the two synthetic accounts, canonical formatting (`json.dumps(..., indent=2)` plus a
  trailing newline), 30 to 40 cases, file size under 80 KB, and that principals and buckets
  referenced by a request exist in the environment.

Run it alone with `.venv/bin/python -m pytest -q tests/regression/test_iam_cases.py`.

### Adding or adjudicating a case

1. Find the documentation sentence that fixes the outcome and write the case from it.
2. Run the test. If the evaluator disagrees, do **not** change `expected`: set
   `status: "disputed"`, add a `note` describing the documented rule and the observed decision,
   and open the question with the maintainers.
3. When a dispute is resolved in favour of the documentation, fix the evaluator and flip the
   case to `confirmed`; when it is resolved against the case (for example a misreading of the
   documentation), correct the case and its citation.

### Deviations the corpus found, and what changed

The first run of the corpus against the evaluator produced three disputed cases. All three were
resolved in favour of the documentation; each fix has a regression test in
`tests/regression/test_fixed_bugs.py` in addition to the corpus case.

| Case | Documented rule | What the evaluator did | Fix |
| --- | --- | --- | --- |
| `negated-operator-with-absent-key-is-true` | A negated operator (`StringNotEquals`, `ArnNotLike`, ...) is true when the key is not present, so a `Deny` using it applies (condition operators page, "Important" note). | Returned a non-match for every non-`IfExists` operator when the key was known to be absent, so the request was allowed. | `attackpath.iam.conditions`: an absent key makes negated operators true. |
| `forallvalues-absent-key-evaluates-true` | `ForAllValues` returns true if there are no context keys in the request (multivalued context keys page). | Returned a non-match, so the request was implicitly denied. | Same place: `ForAllValues` is true for the empty set; `ForAnyValue` stays false. |
| `policy-variable-without-version-is-literal` | Without `Version: 2012-10-17`, `${aws:username}` is a literal string (policy variables page, note on `Version`). | Substituted variables regardless of `Version` and allowed the request; the parser only warned. | `attackpath.iam.matching` / `evaluator`: variables are interpreted only in `2012-10-17` documents. |

Building the corpus also surfaced a question the author of the corpus deliberately did not turn
into a case for lack of a single citable sentence: a same-account bucket policy whose principal is
the *account root* was treated like one naming the user, granting access on its own. The
`Principal` element documentation describes an account principal as a delegation to the account,
so the evaluator now requires an identity-based allow in that situation (as it already did for
account-root trust policies); case `same-account-root-principal-delegates-to-account` records it.

## Validating against the IAM policy simulator

`scripts/validate_iam_cases.py` can replay the simulator-supported cases through
`iam:SimulateCustomPolicy` and compare three answers per case: the documented expectation, the
simulator's decision and this project's evaluator. It is opt-in and read-only:

```bash
# print the plan only (no AWS call, exit status 1)
.venv/bin/python scripts/validate_iam_cases.py --profile <name>

# run it
.venv/bin/python scripts/validate_iam_cases.py --profile <name> --region us-east-1 --confirm \
    --output /tmp/iam-cases-simulation.json
```

What the script does when confirmed:

1. Creates a boto3 session lazily (nothing is imported or called at module import time) and
   registers a botocore `before-call` handler that raises for any operation other than
   `iam:SimulateCustomPolicy` and `sts:GetCallerIdentity`, failing closed when an operation cannot
   be identified. This is the same pattern as `attackpath.aws.safeguards`, with a two-operation
   allow list.
2. Calls `sts:GetCallerIdentity` and refuses to continue with root credentials.
3. For each case with `simulator.supported: true`, builds the request: identity policies
   (user inline, attached managed and group policies, as resolved by the evaluator) in
   `PolicyInputList`; the boundary in `PermissionsBoundaryPolicyInputList`; the bucket policy in
   `ResourcePolicy` together with `CallerArn` (the case principal) and `ResourceOwner` (the bucket's
   account); `ResourceArns` and `ActionNames` from the request; `ContextEntries` from the request
   context, with the data type inferred from the key and value (`string`, `stringList`, `boolean`,
   `numeric`, `ip`, `date`). Keys that this project derives from the principal
   (`aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:username`, `aws:PrincipalTag/*`) are supplied
   when a policy references them. A principal without identity policies gets a placeholder `Deny`
   on a resource no case uses, because `PolicyInputList` must not be empty.
4. Maps `EvalDecision` (`allowed`, `explicitDeny`, `implicitDeny`) to the corpus vocabulary,
   prints a table (case id, expected, simulator, evaluator, match) plus any
   `MissingContextValues`, and exits 0 only when every simulated case agrees with both the
   expectation and the evaluator. Disputed cases are simulated too; they are the ones a run is
   most useful for.
5. Optionally writes the results as JSON (file mode `0600`). The corpus itself is never modified.

The IAM permissions needed are `iam:SimulateCustomPolicy` and `sts:GetCallerIdentity`.

**Status:** validation against the simulator has **not** been run for this corpus. Unless the
project README records a run (date, caller type and result), treat the corpus as
documentation-sourced only.

### Simulator limitations

* **No "indeterminate".** The simulator returns `allowed`, `explicitDeny` or `implicitDeny`. A
  condition key that no `ContextEntry` supplies is treated as absent and listed under
  `MissingContextValues`; the project's `indeterminate` case is therefore marked
  `simulator.supported: false` (supply a value to simulate one branch).
* **Context values must be supplied.** Apart from a few principal and organization keys that
  the simulator populates itself, every key referenced by a policy needs a `ContextEntry`. The
  corpus models an absent key by omitting the entry.
* **It cannot model missing policy documents.** The evaluator reports `indeterminate` when an
  attached policy or a boundary is not in the snapshot; the simulator only knows the documents it
  is given. The script refuses to simulate such a case.
* **Principal and ownership are synthetic.** `CallerArn` must be an IAM user ARN (resource
  policy simulation is not supported for roles) and is used only to match the `Principal`
  element; `ResourceOwner` decides whether a bucket is same-account or cross-account. The
  corpus accounts are fictitious, so a simulator that insists on an existing caller would need
  the ARNs rewritten to a real account.
* **One boundary, one resource policy, no groups.** Group policies are flattened into
  `PolicyInputList`; only one `ResourcePolicy` and one boundary can be passed.
* **Results can differ from the live environment** (AWS says so explicitly): service-specific
  authorization rules, VPC endpoint policies, SCPs and RCPs are outside both the simulator run
  and this corpus.
