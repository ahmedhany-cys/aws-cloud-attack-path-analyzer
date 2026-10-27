# Input format

The analyzer accepts two kinds of input:

1. **An environment snapshot** (one JSON file): identities, policies and resources of one AWS
   account. Produced by hand (fixtures), by an export pipeline, or by `attackpath aws-scan`.
2. **Standalone IAM policy documents** (a single policy file, or a directory of them): analyzed in
   *policy-only mode*, where each document becomes the inline policy of a synthetic role in the
   reserved account `000000000000`. Trust relationships, resources and attachments are unknown in
   this mode, and the report says so.

All inputs are parsed with the standard library `json` module only, after a size check (default
25 MiB, `--max-input-mb`) and a nesting-depth check (64 levels). Unknown top-level or statement
elements are rejected rather than ignored, so a typo cannot silently drop a policy element.

## Snapshot schema (version 1.0)

```jsonc
{
  "schema_version": "1.0",
  "metadata": {
    "name": "synthetic-demo-account",
    "description": "free text",
    "synthetic": true,              // reports carry a prominent notice when true
    "source": "fixture",            // fixture | aws-scan | export
    "generated_at": "2026-10-27T00:00:00Z",
    "generator": "free text",
    "regions": ["us-east-1"]
  },
  "account_id": "111111111111",     // 12 digits, required
  "coverage": {                     // what the snapshot does and does not contain
    "services": {
      "iam": "complete",            // complete | partial | missing | unknown
      "lambda": {"status": "partial", "notes": ["eu-west-1 not inventoried"]}
    },
    "notes": ["free text"]
  },
  "external_principals": [          // optional: accounts you know about
    {"arn": "arn:aws:iam::222222222222:root", "description": "partner", "known": true}
  ],
  "managed_policies": [
    {
      "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
      "name": "AdministratorAccess",            // optional, derived from the ARN
      "is_aws_managed": true,                   // optional, derived from the ARN
      "document": { "Version": "2012-10-17", "Statement": [ ... ] }
    }
  ],
  "groups": [
    {"name": "data-analysts", "path": "/", "inline_policies": {"Name": { ... }}, "attached_policies": ["arn..."]}
  ],
  "users": [
    {
      "name": "ci-deployer",
      "arn": "arn:aws:iam::111111111111:user/ci-deployer",   // optional, derived from name and path
      "path": "/",
      "groups": ["data-analysts"],
      "inline_policies": {"deploy": { ... }},
      "attached_policies": ["arn:aws:iam::aws:policy/..."],
      "permissions_boundary": "arn:aws:iam::111111111111:policy/boundary",
      "access_keys": [{"key_id": "SYNTHETIC-KEY-ID-0001", "status": "Active", "created": "...", "last_used": "..."}],
      "mfa_enabled": false,
      "console_access": true,
      "tags": {"team": "platform"}
    }
  ],
  "roles": [
    {
      "name": "lambda-image-resizer",
      "trust_policy": { "Version": "2012-10-17", "Statement": [ ... ] },   // required
      "inline_policies": { ... },
      "attached_policies": [ ... ],
      "permissions_boundary": null,
      "description": "free text",
      "last_used": "2026-01-01T00:00:00Z",
      "tags": { ... }
    }
  ],
  "s3_buckets": [
    {
      "name": "customer-pii-exports",
      "arn": "arn:aws:s3:::customer-pii-exports",          // optional
      "account_id": "111111111111",                        // optional, defaults to the snapshot account
      "region": "us-east-1",
      "bucket_policy": { ... } | null,
      "public_access_block": {
        "block_public_acls": true, "ignore_public_acls": true,
        "block_public_policy": true, "restrict_public_buckets": true
      },
      "acl_public_read": false,
      "acl_public_write": false,
      "encryption": "aws:kms",
      "sensitivity": "high",                               // high | medium | low (default unknown)
      "description": "free text",
      "tags": { ... }
    }
  ],
  "lambda_functions": [
    {
      "name": "image-resizer",
      "arn": "arn:aws:lambda:us-east-1:111111111111:function:image-resizer",   // optional
      "region": "us-east-1",
      "runtime": "python3.12",
      "role_arn": "arn:aws:iam::111111111111:role/lambda-image-resizer",
      "resource_policy": { ... } | null,
      "description": "free text",
      "tags": { ... }
    }
  ]
}
```

### Validation rules worth knowing

* `account_id` must be a 12-digit string; principal ARNs must be IAM ARNs of the right type.
* Duplicate ARNs (or duplicate group names) are rejected.
* Every trust-policy and bucket-policy statement must have a `Principal` or `NotPrincipal`.
* `Action` and `NotAction` (likewise `Resource`/`NotResource`, `Principal`/`NotPrincipal`) cannot
  appear in the same statement; `Effect` must be exactly `Allow` or `Deny`.
* Condition values may be strings, numbers or booleans (as AWS accepts); they are normalized to
  strings.
* Counts above the safety limits (25 000 principals, 50 000 resources by default) are rejected.
* A missing `coverage` section produces an informational finding: the analyzer then cannot tell
  whether the snapshot is complete.

### Sensitivity

The analyzer does not classify data. Bucket sensitivity comes from the `sensitivity` field; the
AWS collector derives it from a `DataClassification` or `Sensitivity` tag whose value is
`high`, `medium` or `low`. Buckets without a declared sensitivity are treated as `unknown` (a
middle weight in scoring) and are not considered reachability targets.

### Why the AWS-managed policy documents are included

`attached_policies` are resolved against `managed_policies`. If a referenced document is missing,
the evaluator cannot know what it grants: it records the gap, produces a coverage finding and marks
dependent decisions `indeterminate`. The collector therefore stores the default version of every
attached managed policy, including AWS-managed ones.

## Policy-only mode

A policy document is recognized by its top-level `Statement`. A directory may only contain policy
documents (one snapshot per analysis keeps reports unambiguous). Each file becomes
`arn:aws:iam::000000000000:role/<file-stem>`; file stems are sanitized to IAM-safe characters and
de-duplicated. Checks that need trust relationships, resources or attachments (paths,
sensitive access, exposure) produce nothing in this mode; statement-level checks (administrative
access, wildcards, IAM/credential/Lambda write permissions, broad `iam:PassRole`, conditional
`Deny` handling) run normally.
