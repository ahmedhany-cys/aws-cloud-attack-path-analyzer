# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
