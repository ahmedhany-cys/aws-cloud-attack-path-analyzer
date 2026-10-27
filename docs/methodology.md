# Methodology

This page explains how the analyzer reaches its conclusions and, just as importantly, how it
labels the ones it cannot reach. The design goal is simple to state: **never convert an unknown
into a decision**. When the configuration proves something, the finding says *observed*; when it
needs context the snapshot does not contain, the finding says so and is scored down.

## Five classes of statement

Every output of the analyzer belongs to one of these classes. The first column is the
vocabulary used in reports.

| Reported as | Meaning | Example |
|---|---|---|
| `observed` (evidence kind) | A configuration fact read directly from the snapshot | a statement allows `*` on `*`; a trust policy names `Principal: "*"` |
| `inferred` | Several configuration facts combined by the evaluator or the graph | user → assume role → read bucket (each hop observed, the chain inferred) |
| `hypothetical` | Needs an assumption the snapshot cannot confirm | a principal in another account also has `sts:AssumeRole` in its own policies |
| `indeterminate` | The evaluator could not decide | an Allow guarded by `aws:SourceVpce`; a Deny guarded by `aws:SourceIp`; an attached policy whose document is missing |
| coverage finding | Something the snapshot does not contain at all | a region not inventoried, a policy document not exported |

Preconditions (for example "caller must present the configured `sts:ExternalId`") are listed on
each finding and reduce its score.

## Evaluation pipeline

1. **Parse** the snapshot or policy files with strict validation (`docs/input-format.md`).
2. **Resolve** each principal's effective policy set: inline policies, attached managed policies,
   and (for users) group policies. Missing documents are recorded as limitations.
3. **Evaluate** concrete questions with the tri-state evaluator (see below).
4. **Build the graph**: observed structure (membership, attachments, trust, execution and
   instance roles), `can-assume` and `can-access` capability edges, each carrying the statements
   that justify it, and `network-exposed` edges from the internet to instances whose security
   groups and public address admit it.
5. **Search paths** from every user, role, function, instance, external account, the anonymous
   node and the internet node to administrative principals and sensitive buckets, within
   configured limits.
6. **Run checks**, each producing findings with evidence, preconditions, impact, remediation,
   verification steps and references.
7. **Score** findings with the transparent model in `docs/scoring.md`.
8. **Render** JSON, Markdown and HTML with escaping.

## Implemented IAM semantics

The evaluator implements the following parts of the
[AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html):

* **Explicit deny precedence.** Any applicable `Deny` (identity, boundary or resource policy)
  produces `explicit-deny`. A `Deny` whose condition cannot be decided produces `indeterminate`,
  never `allowed`.
* **Implicit deny.** No applicable `Allow` produces `implicit-deny`.
* **Action matching.** Case-insensitive, `*` and `?` wildcards, `NotAction`.
* **Resource matching.** Case-sensitive, `*` and `?` wildcards, `NotResource`; statements without
  a resource element (trust policies) apply to the attached resource.
* **Policy variables.** `${aws:username}`, `${aws:PrincipalTag/key}` and friends are substituted
  when the context provides them (with `${var, 'default'}` support); unresolved variables make
  the match `UNKNOWN`. Only documents with `Version: 2012-10-17` interpret variables; in a
  document without that version `${...}` is literal text, as AWS specifies.
* **Principal matching.** `*`, `{"AWS": "*"}`, account root ARNs and bare account ids (any
  principal of that account), specific user and role ARNs, assumed-role session ARNs normalized to
  their role, service principals, federated principals, `NotPrincipal`. Canonical user ids cannot
  be mapped offline and yield `UNKNOWN`.
* **Conditions.** 26 operators: `String*` (including `IgnoreCase` and `Like`), `Arn*`, `Bool`,
  `Numeric*`, `Date*`, `IpAddress`/`NotIpAddress` (IPv4 and IPv6, CIDR), `Null`, `BinaryEquals`
  (as string equality); the `...IfExists` suffix; `ForAnyValue:` and `ForAllValues:` set
  operators; multiple keys in one block combine with AND; multiple values for one key with OR.
  A key missing from the request context yields `UNKNOWN`. A key known to be absent follows the
  documented rules: `...IfExists` is true, a negated operator (`StringNotEquals`, `ArnNotLike`,
  `NotIpAddress`, ...) is true, `ForAllValues` is true for the empty set, and every other
  operator is false. An unsupported operator yields `UNKNOWN` with a reason.
* **Permissions boundaries.** Effective identity permissions are the intersection of identity
  policies and the boundary; a boundary `Deny` applies; a missing boundary document makes results
  indeterminate. Same-account resource policies that name the principal are not limited by the
  boundary.
* **Resource-based policies.** Same account: identity allow *or* resource allow suffices when
  the resource policy names the principal (or everyone) directly; a resource policy that only
  names the account root delegates to the account, so the identity policy must allow the action
  as well. Cross account: both are required. Implemented for S3 bucket policies, Lambda resource
  policies and role trust policies.
* **Role trust.** Same account and the trust policy names the principal's ARN: the trust policy
  alone grants `sts:AssumeRole`. Same account and the trust policy names the account root: the
  caller also needs an identity-policy allow. Cross account: the caller needs both; the external
  identity policy is outside the snapshot and becomes a precondition. `Deny` statements in trust
  policies are honoured.
* **Request context derived from the snapshot.** `aws:PrincipalArn`, `aws:PrincipalAccount`,
  `aws:PrincipalType`, `aws:username` (users only), `aws:PrincipalTag/*`, `aws:ResourceAccount`,
  `aws:ResourceTag/*` for buckets, and anything a check passes explicitly (for example
  `sts:ExternalId` when testing a hypothesis). Everything else is unknown.

What is *not* implemented is listed in `docs/limitations.md`.

## The checks

| Check id | Question asked | Evidence kind | Notes |
|---|---|---|---|
| `ADMIN` | Are eight high-impact actions on `*` all allowed? (`iam:CreateUser`, `iam:AttachUserPolicy`, `iam:CreateAccessKey`, `sts:AssumeRole`, `s3:GetObject`, `ec2:RunInstances`, `lambda:CreateFunction`, `kms:Decrypt`) | observed; indeterminate when some probes depend on unresolved context | A missing policy document alone never produces this finding |
| `WILDCARD` | Does an Allow grant `*` or `service:*` on a broad resource pattern, and does any Deny cancel it? | observed; inferred when conditional; indeterminate when a Deny with unknown condition applies | Suppressed for administrative principals |
| `TRUST-ANONYMOUS` | Does a trust policy admit `Principal: "*"`? With which conditions? | observed; inferred when narrowed by `aws:PrincipalOrgID`-style keys; indeterminate for unknown conditions | |
| `TRUST-CROSS-ACCOUNT` | Does a trust policy admit another account or one of its principals? Is `sts:ExternalId` required? Is the account a declared partner? | observed | Tags: `missing-external-id`, `external-id-required` |
| `ASSUME-BROAD` | Is `sts:AssumeRole` allowed on a broad resource pattern? Which roles in the snapshot actually admit the principal? | observed / indeterminate | Lists assumable and administrative targets from the graph |
| `PASSROLE-BROAD` | Is `iam:PassRole` allowed broadly without `iam:PassedToService`? Which paired service permissions and service-trusted roles exist? | observed / indeterminate | Configuration finding; the workflow is not simulated |
| `IAM-WRITE` | Which policy/attachment/trust-modifying IAM actions are allowed on broad patterns? | observed / indeterminate | Twelve probed actions |
| `CREDENTIAL-WRITE` | Which credential-management actions are allowed for users other than the caller? | observed / indeterminate | Lists administrative users in the snapshot |
| `LAMBDA-WRITE` | Which function code/configuration actions are allowed broadly? Which execution roles are privileged? | observed / indeterminate | |
| `S3-PUBLIC-POLICY` | Does the bucket policy grant to everyone? Does Block Public Access make it inert? | observed; indeterminate for conditional grants | Tag `mitigated-by-block-public-access` |
| `S3-PUBLIC-ACL` | Are public ACL grants recorded? Does `IgnorePublicAcls` neutralize them? | observed | |
| `S3-EXTERNAL-ACCESS` | Does the bucket policy grant to other accounts? | hypothetical | The other account's identity policies are unknown |
| `LAMBDA-PUBLIC-INVOKE` / `LAMBDA-EXTERNAL-INVOKE` | Does the function's resource policy allow invocation by everyone / by another account? What does the execution role reach? | observed / hypothetical | |
| `EC2-PUBLIC-EXPOSURE` | Is a running instance with a public address reachable from `0.0.0.0/0` or `::/0` through its security groups? On which ports, and what does its instance role reach? | observed (confidence medium when the subnet's routing is unknown) | Management and database ports (SSH, RDP, WinRM, Docker, common databases) set the exposure factor to 1.0 and floor escalation at 0.6 and asset sensitivity at 0.5 (the host itself is a foothold); otherwise the instance role's privilege and the sensitivity of the buckets it reaches set those factors |
| `EC2-IMDSV1` | Does a running instance with an IAM role still accept IMDSv1 (session tokens optional)? | observed | Role credentials become readable through any request-forgery or local-file-read flaw |
| `SENSITIVE-ACCESS` | Can a non-administrative principal read, list, write, delete or re-policy a bucket declared high or medium sensitivity? | observed / indeterminate | Records explicit denies; tags workload roles (service-trusted, used by functions or instances); access that exists only through a public bucket policy is reported once by `S3-PUBLIC-POLICY` |
| `PATH-ADMIN` | Can an identity reach an administrative principal through assume-role, execution-role, instance-role or network-exposure hops? | observed / inferred / hypothetical / indeterminate (weakest hop) | Administrative sources are not searched |
| `PATH-SENSITIVE` | Can an identity (or the internet) reach a sensitive bucket through at least one transition? | weakest hop | Function → own role → bucket and instance → own role → bucket are reported by `SENSITIVE-ACCESS` instead; paths entering through `network-exposed` are tagged `network` and `multi-service` |
| `EVAL-INDETERMINATE` | Which statements could not be fully evaluated, and why? | indeterminate | One finding per statement, capped at low |
| `COVERAGE-PARTIAL` / `COVERAGE-UNRESOLVED-POLICY` / `COVERAGE-UNRESOLVED-ROLE` | What does the snapshot not contain? | observed | Pinned severities; make the absence of findings explicit |

## Reachability search

Sources: users, roles, functions, instances, external accounts and principals named in trust or
bucket policies, the anonymous node and the internet node. Transitions: `can-assume`
(evaluator-confirmed), `executes-as` and `runs-as` (observed), and `network-exposed`
(hypothetical: it assumes a compromise of the exposed instance). Targets: administrative
principals, and buckets declared high or medium sensitivity reached through a final `can-access`
edge. Limits: depth 4 (`--max-depth`), 5 paths per source/target pair, 10 000 paths in total;
truncation is reported. The primary path reported for a pair is the shortest, then the one with
the strongest evidence, then the highest confidence.

Deliberately excluded from path search: access edges that exist only because of a public bucket
policy, access edges blocked by `RestrictPublicBuckets`, administrative sources (they are already
administrative), and `can-assume` edges whose only uncertainty is a missing policy document.

## Network exposure model

The network model is intentionally small and conservative:

* **Reachable from the internet** means: the instance is running, has a public address, at least
  one of its security groups has an inbound rule whose source is `0.0.0.0/0` or `::/0`, and the
  snapshot does not say that the subnet lacks an internet-gateway route (`internet_facing` is
  `true` or unknown). When it is unknown, the finding carries that precondition and a medium
  confidence. The AWS collector derives `internet_facing` from the subnet's route table (or the
  VPC's main table).
* **Security-group sources** that are other groups or prefix lists are recorded but not resolved:
  an instance behind a load balancer whose group admits only the balancer's group is *not*
  reported as exposed, because the balancer is not in the snapshot.
* **The `network-exposed` edge is hypothetical.** Reaching an open port is not code execution; the
  edge therefore carries the precondition that a listening service be exploitable or accept weak
  credentials, and every path that starts at the internet node is capped at `high` by the
  evidence rules in `docs/scoring.md`. The `EC2-PUBLIC-EXPOSURE` finding itself is an observed
  configuration fact and is scored on its own factors.
* **`runs-as` is observed structure.** Code on an instance can obtain its instance-profile role's
  credentials from the metadata service; whether that needs IMDSv2 tokens is reported separately
  by `EC2-IMDSV1`.
* Not modelled: network ACLs, egress rules, load balancers and target groups, VPC peering, Transit
  Gateway, PrivateLink, host firewalls, Elastic IPs attached to network interfaces other than the
  primary one, IPv6-only reachability nuances, and what actually listens on a port.

## Scope decision: capabilities that change configuration

Permissions that would let a principal change IAM or workload configuration (`iam:PassRole`,
policy attachment and modification, credential creation, Lambda code updates) are reported as
individual configuration findings with least-privilege remediation. They are **not** chained into
multi-step scenarios by the path search. This keeps every path in a report backed by evaluator
decisions over existing configuration rather than by assumptions about actions an identity might
take, and it keeps the remediation advice concrete: scope the grant.

## Cross-checking the evaluator

* The evaluator's unit tests encode the documented IAM evaluation-logic cases: explicit deny
  precedence, boundary intersection, same-account versus cross-account resource policies, role
  trust with and without identity permissions, `IfExists` and `Null` semantics, set operators.
* `tests/regression/iam_cases.json` is an independently specified corpus: every expected outcome
  was derived from a cited AWS documentation page *before* the evaluator ran, and no expectation
  is ever adjusted to match the evaluator (`docs/iam-regression-cases.md`). Its first run found
  three deviations (negated operators and `ForAllValues` with an absent key, policy variables in
  documents without `Version: 2012-10-17`), all fixed; `scripts/validate_iam_cases.py` can replay
  the same cases through the IAM policy simulator when an operator opts in.
* Every finding that depends on an authorization decision lists a read-only verification command
  using the IAM policy simulator (`aws iam simulate-principal-policy`) so the decision can be
  checked against AWS itself for the real account.
* The built-in self-check (`python -m attackpath validate`) replays the twelve scenarios and
  compares the outcome with recorded expectations; `docs/incident-scenarios.md` is generated from
  the same run.

A live comparison against AWS tooling for a real account was not part of this release; the
analyzer never makes network calls during offline analysis, so such a comparison is a manual
verification step for the operator.
