# Scoring model

Scores exist to order work, not to prove anything. A finding scored 82 is not "82 % likely to be
exploitable"; it is a configuration relationship that the model ranks above one scored 60. Every
finding carries its full breakdown so a reviewer can disagree with the arithmetic from the report
alone.

## Arithmetic

```
base   = 100 × Σ(weight_f × value_f) / Σ(weight_f)              value_f ∈ [0, 1]
raw    = base × evidence_multiplier × confidence_multiplier × precondition_multiplier
precondition_multiplier = max(floor, 1 − penalty_per_item × number_of_preconditions)
severity = highest threshold reached by raw, then capped by evidence kind, then per-check overrides
```

Default weights, multipliers and thresholds live in
[`src/attackpath/data/scoring.toml`](../src/attackpath/data/scoring.toml) and can be replaced with
`--scoring-config my-scoring.toml` (the file is validated: every factor needs a weight, thresholds
must decrease, multipliers must be within 0..1).

## Factors

| Factor | Weight | Meaning | Typical sources |
|---|---:|---|---|
| `permission_breadth` | 20 | How many actions and resources the grant covers | action and resource wildcard breadth, access classes on a bucket |
| `escalation_potential` | 25 | Could the relationship lead to more privilege, up to full administrative control | administrative probe, IAM write actions, assumable administrative roles |
| `resource_sensitivity` | 20 | Sensitivity of what becomes reachable | declared bucket sensitivity, reach of a role |
| `trust_boundary` | 15 | Does the relationship cross an account or anonymous boundary | trust-policy classification, bucket-policy principals |
| `exposure` | 10 | How exposed the starting identity is | long-lived keys, console without MFA, external or anonymous caller, workload role, instance reachable from the internet |
| `reachability` | 10 | How direct the relationship is | hop count of a path, paired permission requirements |

Factor values are heuristics chosen per check and documented in each finding's `rationale` text.

## Evidence and confidence

| Evidence kind | Multiplier | Severity cap | Meaning |
|---|---:|---|---|
| `observed` | 1.00 | none | a direct configuration fact |
| `inferred` | 0.90 | none | several configuration facts combined (for example a multi-hop path) |
| `hypothetical` | 0.70 | high | depends on assumptions outside the snapshot (another account's policies) |
| `indeterminate` | 0.50 | medium | the evaluator could not decide (unknown condition, missing document) |

Confidence multiplies in as `high` 1.0, `medium` 0.9, `low` 0.75. Each stated precondition
removes 8 % down to a floor of 50 %.

## Thresholds

| Severity | Raw score |
|---|---:|
| critical | ≥ 80 |
| high | ≥ 60 |
| medium | ≥ 40 |
| low | ≥ 20 |
| informational | < 20 |

## Per-check overrides

Coverage findings are pinned (`COVERAGE-PARTIAL` informational, unresolved policy or role low)
because they describe what the analyzer could not see rather than a risk; evaluation-limitation
findings are capped at low for the same reason.

## Worked example

`User legacy-automation can reach role ops-admin-legacy in 1 step(s)` from the sample environment:

| Factor | Value | Rationale |
|---|---:|---|
| permission_breadth | 1.0 | administrative permissions at the end of the path |
| escalation_potential | 1.0 | reaches administrative permissions |
| resource_sensitivity | 1.0 | every resource in the account |
| trust_boundary | 0.0 | path stays inside the account |
| exposure | 0.7 | human identity; has active long-lived access keys |
| reachability | 1.0 | 1 hop |

base = 100 × (20 + 25 + 20 + 0 + 7 + 10) / 100 = 82; observed evidence, high confidence, no
preconditions → raw 82 → **critical**. The same path reported for an identity with MFA and no
keys scores 79 (exposure 0.4) → **high**, which is the intended behaviour: the break-glass
administrator is a known, protected identity; the automation user with a 2022 access key is not.

## Tuning advice

* Raise `trust_boundary` if cross-account access is your main concern; raise `exposure` if
  credential hygiene is.
* Lower `thresholds.critical` only if you are prepared to act on more findings immediately.
* Keep the evidence multipliers below 1.0 for `hypothetical` and `indeterminate`: they are what
  stops unverifiable findings from crowding out verified ones.
