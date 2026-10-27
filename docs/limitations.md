# Limitations

The analyzer reasons about a static snapshot with a deliberately conservative evaluator. The
limitations below are structural; where the analyzer meets one at run time it records it in the
report (as an `indeterminate` decision, an `EVAL-INDETERMINATE` finding or a coverage finding)
instead of guessing.

## Authorization semantics not implemented

| Area | Status | Consequence |
|---|---|---|
| Service control policies (SCPs) and resource control policies | not modelled | A permission the account grants may be blocked at the organization level without the analyzer knowing; findings may overstate what is possible. |
| Session policies, `sts:AssumeRole` policy parameters, source identity | not modelled | Sessions may be narrower than the role. |
| VPC endpoint policies | not modelled | Access through an endpoint may be narrower. |
| IAM Identity Center permission sets, federated sessions | not modelled; federated principals in trust policies are recorded but not matched | Human access through SSO is invisible unless exported as roles. |
| Resource-based policies other than S3 bucket policies, Lambda resource policies and role trust policies (KMS key policies, SQS, SNS, Secrets Manager, ECR, ...) | not modelled | Access granted or denied by those policies is not evaluated; the services are not in the snapshot schema. |
| S3 object ACLs, object ownership settings, access points, account-level Block Public Access | not modelled (bucket ACLs are recorded only as public-read / public-write booleans) | Public-exposure findings consider bucket policies, bucket ACL flags and bucket-level Block Public Access only. |
| Service-specific authorization behaviour (for example `lambda:FunctionUrlAuthType` context, S3 `s3:x-amz-acl` conditions, KMS grants) | request-time context keys yield `indeterminate` | Such statements appear as evaluation-limitation findings. |
| `NotPrincipal` with `Allow` | parsed and evaluated literally, with a parser warning | AWS discourages the construct; results should be reviewed manually. |
| Multivalued context keys with single-valued operators | evaluated as "any value matches" | AWS semantics for this combination are subtle; prefer explicit set operators. |
| `BinaryEquals` | evaluated as string equality | Base64 payload comparison is rarely relevant to posture analysis. |
| Resource ARN case sensitivity | matched case-sensitively | A few services match case-insensitively; a pattern that differs only by case is reported as not matching. |
| Policy variables | substituted only when the snapshot provides the value (`aws:username`, principal and resource tags); otherwise `UNKNOWN` | Statements scoped with other variables are reported as indeterminate. |
| Request-time conditions (`aws:SourceIp`, `aws:SourceVpce`, `aws:MultiFactorAuthPresent`, `aws:SecureTransport`, `aws:CurrentTime`, ...) | `UNKNOWN` unless a check supplies a hypothesis explicitly | The condition becomes a precondition on the finding; the policy simulator can resolve it for the real account. |

## Inventory limitations

* The snapshot describes one account. Principals of other accounts appear as external nodes with
  unknown permissions; conclusions involving them are `hypothetical`.
* Only IAM, S3, Lambda and EC2 (instances, security groups, route tables) are inventoried. Other
  compute and data services (ECS, EKS, RDS, DynamoDB, ...) are outside the snapshot schema.
* Lambda functions, instances and security groups are collected for one region per scan; other
  regions must be scanned separately and are otherwise reported as coverage gaps only if the
  snapshot declares them.
* The instance-profile → role mapping comes from the IAM listing; when IAM is not inventoried,
  instances keep their profile ARN but no `role_arn`, and the collector records a coverage note.
* Attached managed-policy documents must be present in the snapshot. Without them the affected
  principal's decisions are indeterminate and a coverage finding is raised.
* Group membership, access keys, MFA and console state come from the snapshot as recorded; the
  analyzer does not verify them.
* Data sensitivity is declared (field or tag), never inferred from content.

## Analysis limitations

* **Reachability model.** Paths are built from `can-assume`, `executes-as`, `runs-as` and
  `network-exposed` transitions. Permissions that would allow changing configuration
  (`iam:PassRole`, policy modification, credential creation, function code updates) are reported
  as findings in their own right and are not chained into multi-step paths (see the scope decision
  in `docs/methodology.md`).
* **Network model.** Exposure is decided from security-group ingress, the public address and (when
  known) the subnet's internet-gateway route. Network ACLs, egress rules, load balancers, VPC
  peering, Transit Gateway, PrivateLink, host firewalls and the software actually listening on a
  port are not modelled: an open port is reported as exposure, never as a confirmed vulnerability,
  and every path through it is hypothetical. Security-group and prefix-list sources are not
  resolved, so an instance reachable only through another resource's group is not reported.
* **Bounded search.** Depth, per-pair and total path limits can truncate enumeration on large
  graphs; the report says when that happened.
* **Administrative probe.** "Administrative" means all eight probed high-impact actions are allowed
  on `*`. A principal with slightly narrower but still dangerous permissions is reported by the
  wildcard, IAM-write and credential-write checks instead.
* **Breadth heuristics.** Action and resource breadth are heuristics over patterns, not counts of
  the actual actions a service defines.
* **Scoring is heuristic.** See `docs/scoring.md`. A critical finding is a priority, not a proof.
* **No live verification.** Offline analysis never contacts AWS. Verification commands in each
  finding are read-only suggestions for the operator to run.
* **Policy-only mode** analyzes documents in isolation: no trust, resources or attachments, so
  only statement-level checks apply.

## What the analyzer will not do

* It does not apply remediation, change policies or create resources.
* It does not attempt any action against an account; the AWS adapter is read-only by
  construction and opt-in.
* It does not infer that an exploitable path exists from a theoretical permission chain; it
  reports the configuration relationship, its evidence and the conditions under which it matters.
