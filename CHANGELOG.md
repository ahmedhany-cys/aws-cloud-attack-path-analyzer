# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

* Network exposure and multi-service paths: snapshots may now contain `security_groups` and
  `ec2_instances`; the graph gains `ec2-instance` and `internet` nodes with observed `runs-as`
  (instance → instance-profile role) and hypothetical `network-exposed` (internet → instance)
  edges, and path search starts from instances and from the internet, so a path such as
  *internet → exposed jump host → instance role → sensitive bucket* is reported with its
  preconditions.
* Checks `EC2-PUBLIC-EXPOSURE` (running instance with a public address and security-group ingress
  from `0.0.0.0/0` or `::/0`; management and database ports weigh more) and `EC2-IMDSV1`
  (instance with a role that still accepts IMDSv1), both in the new `network-exposure` category.
* The read-only AWS adapter inventories EC2 (`DescribeInstances`, `DescribeSecurityGroups`,
  `DescribeRouteTables`), maps instance profiles to roles through the IAM listing, derives
  `internet_facing` from route tables and `imdsv2_required` from the metadata options; the
  documented least-privilege policy grows from 18 to 21 actions and `--services` defaults to
  `iam,s3,lambda,ec2`.
* Scenario `11-public-instance-path` with eight recorded expectations; the sample environment
  gains three security groups, four instances and one instance role.
* An independently specified IAM regression corpus (`tests/regression/iam_cases.json`, 41 cases
  whose expected outcomes come from cited AWS documentation pages), the test that replays it, an
  opt-in script that can compare the same cases against the IAM policy simulator
  (`scripts/validate_iam_cases.py`, never run automatically), and `docs/iam-regression-cases.md`.
* A recorded terminal demo (`docs/images/demo.cast` / `demo.gif`, re-recordable with `make demo`
  from `scripts/demo.sh`), a hand-drawn architecture diagram (`docs/images/architecture.svg`) and
  a rendered preview of the HTML report in the README.

### Changed

* Privilege estimates no longer count access that exists only because a bucket policy grants to
  everyone (or that Block Public Access neutralizes) as the identity's own reach; a few sample
  scores moved accordingly.
* Scans that do not request a service report it as `missing` in the coverage section, so an
  older `iam,s3,lambda` selection now yields an informational coverage finding for EC2.

### Fixed

* Three evaluator deviations from the documented IAM semantics, found by the regression corpus:
  a negated condition operator (`StringNotEquals`, `ArnNotLike`, `NotIpAddress`, ...) is now true
  when the key is known to be absent; `ForAllValues` is true for an absent multivalued key; and
  `${...}` policy variables are interpreted only in documents with `Version: 2012-10-17`
  (otherwise they are literal text).
* A same-account bucket policy whose principal is the account root no longer grants access on
  its own: it delegates to the account, so an identity-based allow is required, as AWS specifies
  and as the evaluator already required for account-root trust policies.
* `EVAL-INDETERMINATE` findings no longer truncate the statement label at the first colon when
  the statement has a `Sid`: the evaluator's limitation log now keeps the statement label and the
  reason as separate fields instead of a single string that the check had to split.

### Changed

* README: records the read-only runs of the AWS adapter against a real account on 2026-10-27
  (no results of real-account scans are published).

## [0.1.0] - 2026-10-27

### Added

* Offline analysis of environment snapshots and standalone IAM policy documents.
* Tri-state IAM policy evaluator: explicit deny precedence, permissions boundaries, resource
  policies (S3 bucket policies, Lambda resource policies, role trust policies), same-account and
  cross-account combination rules, 26 condition operators with `IfExists` and set-operator
  support, policy variables, and explicit `indeterminate` results for anything that cannot be
  decided from static configuration.
* Permission-relationship graph with observed structure (membership, attachments, trust, Lambda
  execution roles) and evaluator-backed `can-assume` and `can-access` edges; bounded reachability
  search to administrative principals and sensitive buckets.
* Checks: administrative access, wildcard grants, anonymous and cross-account trust, broad
  `sts:AssumeRole`, broad `iam:PassRole`, IAM write permissions, credential management
  permissions, Lambda write permissions, public and cross-account bucket exposure (with Block
  Public Access handling), public function invocation, sensitive-data access, multi-hop paths,
  evaluation limitations and inventory coverage.
* Transparent, configurable scoring model (TOML) with per-finding breakdowns.
* JSON, Markdown (with Mermaid paths) and standalone HTML reports; CLI with `analyze`,
  `validate`, `version`, `aws-scan` and `dashboard` commands.
* Optional read-only AWS inventory adapter guarded by a botocore operation allow list.
* Optional local Streamlit dashboard.
* Synthetic sample environment, eleven scenario fixtures with recorded expectations, built-in
  self-check, unit/integration/regression/property-based tests, CI with security scanning.
