# Optional AWS setup (read-only scanning)

The analyzer is useful without an AWS account. If you want to analyze a real account, the
`aws-scan` command collects a snapshot through read-only API calls and writes it to a local file
that you then analyze offline like any other snapshot.

## Safety model

* **Opt-in.** Nothing contacts AWS unless you run `aws-scan` with an explicit `--profile`,
  `--region` and `--confirm`. Without `--confirm` the command prints the operations it would call
  and exits without making a request. No scan ever runs at import time, at startup, in tests or in CI.
* **Read-only by construction.** `install_safeguards()` registers a botocore `before-call`
  handler on the session that raises `SafeguardViolationError` for any operation outside the
  allow list below, before a request is built or signed. The handler fails closed when it cannot
  identify an operation. The same allow list generates the IAM policy below, and a test asserts
  that every allow-listed operation is covered by the policy.
* **No root credentials.** The command calls `sts:GetCallerIdentity` first and refuses to continue
  if the caller ARN ends in `:root`.
* **Nothing leaves your machine.** The snapshot is written to `scans/` (Git-ignored) with file
  mode `0600`. Credentials are never printed, logged or written; only the account id and caller
  ARN are shown.
* **Partial results are labelled.** Access-denied responses and exhausted retries become
  coverage notes; a service whose primary listing fails is marked `missing`, one with
  per-resource failures `partial`. The analyzer turns those into coverage findings so that "no
  finding" is never mistaken for "no risk".

## Prerequisites

```bash
pip install ".[aws]"          # boto3 and botocore
aws configure list-profiles   # pick a non-root profile for the target account
```

Use a dedicated IAM role or user for scanning (for example through IAM Identity Center or an
assumed role) and attach only the policy below. Never use the account root user.

## Least-privilege IAM policy for the scan identity

The policy is generated from the adapter's allow list (`attackpath.aws.read_only_policy()`); the
block below is kept identical to the code by a test.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AttackPathReadOnlyInventory",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:GetLoginProfile",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "lambda:GetPolicy",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "s3:ListAllMyBuckets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

| Service | Operations called | Purpose |
|---|---|---|
| STS | `GetCallerIdentity` | account id, root-user refusal |
| IAM | `GetAccountAuthorizationDetails` (paginated) | users, groups, roles, inline and managed policies with documents in one call |
| IAM | `ListAccessKeys`, `ListMFADevices`, `GetLoginProfile` per user | key ids and status (never secrets), MFA state, console access |
| IAM | `GetPolicy`, `GetPolicyVersion` | documents of attached or boundary policies missing from the listing |
| S3 | `ListBuckets`; per bucket `GetBucketLocation`, `GetBucketPolicy`, `GetPublicAccessBlock`, `GetBucketAcl`, `GetBucketEncryption`, `GetBucketTagging` | bucket policies, Block Public Access, public ACL grants, encryption, sensitivity tags |
| Lambda | `ListFunctions` (paginated, one region), `GetPolicy`, `ListTags` per function | execution roles and resource policies |

`s3:GetBucketPolicyStatus` is allow-listed for a future snapshot field but is not called by the
current collector.

## Running a scan

```bash
# 1. Show the plan; no API call is made.
python -m attackpath aws-scan --profile sandbox --region us-east-1

# 2. Collect. Writes scans/<account-id>-<UTC timestamp>.json (mode 0600).
python -m attackpath aws-scan --profile sandbox --region us-east-1 --confirm

# 3. Analyze offline, like any snapshot.
python -m attackpath analyze --input scans/<account-id>-<timestamp>.json --output reports/sandbox/

# Or collect and analyze in one step.
python -m attackpath aws-scan --profile sandbox --region us-east-1 --confirm --analyze --report-dir reports/sandbox/
```

Options: `--services iam,s3` to limit the inventory, `--output path.json` to choose the snapshot
location, `--max-attempts N` for the throttling retry budget (exponential backoff 0.5 s → 20 s cap).
Lambda functions are collected for the `--region` given; run once per region you use and
analyze the snapshots separately (the coverage section records the region).

## What the snapshot contains

Everything `docs/input-format.md` describes: identities with their policies and attachments,
permissions boundaries, access-key ids and status, MFA and console state, managed-policy
documents (including AWS-managed ones that are attached), buckets with policies, Block Public
Access, ACL public flags, encryption and tags, functions with execution roles and resource
policies, and a `coverage` section with per-service status and notes. Bucket sensitivity is
derived from a `DataClassification` or `Sensitivity` tag (`high`/`medium`/`low`); buckets without
one are `unknown` and are not reachability targets, so tag your sensitive buckets or edit the
snapshot before analysis.

Not collected: role descriptions and access-key last-used timestamps (they need `iam:GetRole` and
`iam:GetAccessKeyLastUsed`, which are not allow-listed), resources of other services, other regions'
functions, organization-level policies.

## Cost and audit footprint

The scan creates no resources. IAM, STS and Lambda control-plane requests are not billed per
request on the AWS pricing pages at the time of writing. S3 bucket-configuration requests count as
S3 requests, billed per thousand at a fraction of a cent; a scan makes roughly
`1 + 7 × (number of buckets)` S3 requests. Check the
[S3 pricing page](https://aws.amazon.com/s3/pricing/) for your region. Every call is a management
event that CloudTrail records under the scanning identity, which is desirable: the scan is
visible and attributable.

## Troubleshooting

| Message | Meaning |
|---|---|
| `error: ... The config profile (x) could not be found` | the `--profile` is not in `~/.aws/config` or `~/.aws/credentials` |
| `error: Unable to locate credentials` | the profile has no credentials or the SSO session expired (`aws sso login --profile x`) |
| coverage note `AccessDenied on iam:GetAccountAuthorizationDetails` | the scan identity lacks the policy above; IAM is marked `missing` |
| coverage note `... throttled after N attempts` | raise `--max-attempts` or retry later; the affected resources are listed |
| `error: refusing to scan with root credentials` | use an IAM role or user instead |
| `SafeguardViolationError` | the adapter attempted an operation outside its allow list; this should never happen and is a bug worth reporting |

## Verifying the adapter without an account

`make test` runs the adapter against botocore `Stubber` clients with fake credentials: pagination,
throttling and retry, access-denied handling, missing-policy handling, the root refusal, the
`--confirm` gate and the safeguard that blocks a write operation before any HTTP request. Whether a
live scan was performed for a given release is stated in the README's results section; the test
suite never needs credentials.

## Teardown

Delete the snapshot files in `scans/` when you no longer need them (they describe your account's
identity configuration in detail) and remove the scan identity or policy through your usual IAM
process. The analyzer itself leaves nothing behind in the account.

If the policy was attached inline to an existing user for a one-off scan, remove it afterwards and
confirm that it is gone:

```bash
aws iam delete-user-policy --profile <profile> --user-name <user> --policy-name AttackPathReadOnlyInventory
aws iam list-user-policies --profile <profile> --user-name <user>   # PolicyNames must no longer list it
```

For a role, use `delete-role-policy` / `list-role-policies`; for a customer-managed policy,
`detach-user-policy` or `detach-role-policy` followed by `delete-policy`.
