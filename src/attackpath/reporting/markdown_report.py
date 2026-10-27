"""Markdown report with Mermaid path diagrams (renders on GitHub)."""

from __future__ import annotations

import json

from attackpath.models.finding import AnalysisReport, Finding
from attackpath.reporting.common import (
    HEURISTIC_NOTICE,
    SYNTHETIC_NOTICE,
    group_by_severity,
    md_code,
    md_escape,
    mermaid_path,
    severity_badge,
)


def render_markdown(report: AnalysisReport) -> str:
    out: list[str] = []
    out.append("# AWS Cloud Attack Path Analyzer report")
    out.append("")
    if report.synthetic:
        out.append(f"> **Synthetic environment.** {SYNTHETIC_NOTICE}")
        out.append(">")
    out.append(f"> {HEURISTIC_NOTICE}")
    out.append("")
    out.extend(_summary(report))
    out.extend(_findings(report))
    out.extend(_limitations(report))
    out.extend(_scoring(report))
    return "\n".join(out) + "\n"


def _summary(report: AnalysisReport) -> list[str]:
    counts = report.counts_by_severity()
    out = ["## Summary", ""]
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| Input | {md_escape(report.input_description)} |")
    out.append(
        f"| Environment | {md_escape(report.environment_name)} ({'synthetic' if report.synthetic else report.source}) |"
    )
    out.append(f"| Account | {md_code(report.account_id)} |")
    out.append(f"| Generated | {md_escape(report.generated_at)} |")
    out.append(f"| Tool version | {md_escape(report.tool_version)} |")
    if report.analysis_seconds is not None:
        out.append(f"| Analysis time | {report.analysis_seconds:.3f} s |")
    out.append(f"| Findings | {len(report.findings)} |")
    out.append("")
    out.append("### Findings by severity")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for sev, count in counts.items():
        out.append(f"| {sev.upper()} | {count} |")
    out.append("")
    out.append("### Findings by category")
    out.append("")
    out.append("| Category | Count |")
    out.append("|---|---:|")
    for cat, count in report.counts_by_category().items():
        out.append(f"| {md_escape(cat)} | {count} |")
    out.append("")
    out.append("### Inventory")
    out.append("")
    out.append("| Entity | Count |")
    out.append("|---|---:|")
    for name, count in report.environment_summary.items():
        out.append(f"| {md_escape(name)} | {count} |")
    out.append("")
    out.append("### Coverage")
    out.append("")
    services = report.coverage.get("services", {})
    if services:
        out.append("| Service | Status | Notes |")
        out.append("|---|---|---|")
        for name, entry in services.items():
            out.append(
                f"| {md_escape(name)} | {md_escape(entry.get('status', ''))} | {md_escape('; '.join(entry.get('notes', [])))} |"
            )
    else:
        out.append("No coverage information was declared in the snapshot.")
    out.append("")
    g = report.graph
    out.append("### Graph")
    out.append("")
    out.append(
        f"{g.node_count} nodes, {g.edge_count} edges, {g.paths_found} path(s) found"
        + (" (truncated)" if g.paths_truncated else "")
        + "."
    )
    out.append("")
    return out


def _findings(report: AnalysisReport) -> list[str]:
    out = ["## Findings", ""]
    if not report.findings:
        out.append("No findings.")
        out.append("")
        return out
    out.append("| Severity | ID | Title | Confidence | Evidence |")
    out.append("|---|---|---|---|---|")
    for f in report.findings:
        out.append(
            f"| {severity_badge(f.severity)} | {md_code(f.id)} | {md_escape(f.title)} | {f.confidence.value} | {f.evidence_kind.value} |"
        )
    out.append("")
    for sev, items in group_by_severity(report.findings).items():
        if not items:
            continue
        out.append(f"### {severity_badge(sev)} ({len(items)})")
        out.append("")
        for f in items:
            out.extend(_finding(f))
    return out


def _finding(f: Finding) -> list[str]:
    out: list[str] = []
    out.append(f"#### {md_escape(f.title)}")
    out.append("")
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| ID | {md_code(f.id)} |")
    out.append(f"| Check | {md_code(f.check_id)} |")
    out.append(f"| Category | {md_escape(f.category.value)} |")
    out.append(f"| Severity | {severity_badge(f.severity)} (score {f.score:.1f}) |")
    out.append(f"| Confidence | {f.confidence.value} |")
    out.append(f"| Evidence kind | {f.evidence_kind.value} |")
    if f.affected_principal:
        out.append(f"| Principal | {md_code(f.affected_principal)} |")
    if f.affected_resource:
        out.append(f"| Resource | {md_code(f.affected_resource)} |")
    if f.tags:
        out.append(f"| Tags | {md_escape(', '.join(f.tags))} |")
    out.append("")
    out.append(f"**Description.** {md_escape(f.description)}")
    out.append("")
    out.append(f"**Impact.** {md_escape(f.impact)}")
    out.append("")
    if f.preconditions:
        out.append("**Preconditions**")
        out.append("")
        out.extend(f"- {md_escape(p)}" for p in f.preconditions)
        out.append("")
    if f.evidence:
        out.append("**Evidence**")
        out.append("")
        for ev in f.evidence:
            out.append(f"- {md_code(ev.source)}: {md_escape(ev.detail)}")
        out.append("")
    if f.attack_path:
        out.append("**Path**")
        out.append("")
        out.append("```mermaid")
        out.append(mermaid_path(f.attack_path))
        out.append("```")
        out.append("")
        for i, step in enumerate(f.attack_path, 1):
            out.append(
                f"{i}. {md_code(step.source)} -[{md_escape(step.description)}]-> "
                f"{md_code(step.target)} (confidence {step.confidence.value})"
            )
        out.append("")
    if f.score_breakdown:
        out.append("<details><summary>Score breakdown</summary>")
        out.append("")
        out.append("| Factor | Value | Weight | Rationale |")
        out.append("|---|---:|---:|---|")
        for name, factor in f.score_breakdown.factors.items():
            out.append(
                f"| {md_escape(name)} | {factor.value:.2f} | {factor.weight:g} | {md_escape(factor.rationale)} |"
            )
        b = f.score_breakdown
        out.append("")
        out.append(
            f"base {b.base_score:.1f} x evidence/confidence {b.confidence_multiplier:.2f} "
            f"x preconditions {b.precondition_multiplier:.2f} = {b.raw_score:.1f}"
            + (f"; {md_escape(b.cap_applied)}" if b.cap_applied else "")
        )
        out.append("")
        out.append("</details>")
        out.append("")
    r = f.remediation
    out.append(f"**Remediation.** {md_escape(r.summary)}")
    out.append("")
    if r.steps:
        out.extend(f"{i}. {md_escape(s)}" for i, s in enumerate(r.steps, 1))
        out.append("")
    if r.suggested_policy is not None:
        out.append("Suggested policy (template, validate before use):")
        out.append("")
        out.append("```json")
        out.append(json.dumps(r.suggested_policy, indent=2).replace("```", "'''"))
        out.append("```")
        out.append("")
    if r.policy_assumptions:
        out.append("Assumptions:")
        out.append("")
        out.extend(f"- {md_escape(a)}" for a in r.policy_assumptions)
        out.append("")
    if r.verification_steps:
        out.append("Verification:")
        out.append("")
        out.extend(f"- {md_escape(v)}" for v in r.verification_steps)
        out.append("")
    if f.references:
        out.append("References:")
        out.append("")
        out.extend(f"- <{md_escape(u)}>" for u in f.references)
        out.append("")
    return out


def _limitations(report: AnalysisReport) -> list[str]:
    out = ["## Limitations and warnings", ""]
    if report.limitations:
        out.extend(f"- {md_escape(item)}" for item in report.limitations)
    else:
        out.append(
            "None recorded for this run. See docs/limitations.md for the general limitations of the analyzer."
        )
    out.append("")
    return out


def _scoring(report: AnalysisReport) -> list[str]:
    out = ["## Scoring model", ""]
    weights = report.scoring.get("weights", {})
    out.append(
        f"Source: {md_escape(report.scoring.get('source', 'built-in'))}. Weights: "
        + ", ".join(f"{md_escape(k)}={v:g}" for k, v in weights.items())
        + "."
    )
    out.append("")
    return out
