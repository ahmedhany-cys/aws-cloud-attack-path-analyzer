"""Local Streamlit dashboard over one analyzed snapshot.

Started by ``attackpath dashboard --input <snapshot>`` through
:func:`attackpath.dashboard.launch`, which passes the snapshot path after ``--`` so
that it reaches ``sys.argv``; the ``ATTACKPATH_INPUT`` environment variable is the
fallback. The page runs the same offline analysis as the CLI, makes no network calls,
sends no telemetry and renders no raw HTML: values are shown through Streamlit
elements that escape their input, and snapshot-derived prose goes through ``st.text``
so that policy fragments such as ``"*"`` are not mistaken for Markdown.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from attackpath.analysis.engine import analyze, build_report
from attackpath.exceptions import AttackPathError
from attackpath.graph.model import AttackGraph
from attackpath.models.finding import (
    AnalysisReport,
    EvidenceKind,
    Finding,
    ScoreBreakdown,
    Severity,
)
from attackpath.parser.loader import load_input
from attackpath.reporting import render
from attackpath.reporting.common import HEURISTIC_NOTICE, SYNTHETIC_NOTICE

INPUT_ENV_VAR = "ATTACKPATH_INPUT"
FULL_GRAPH_MAX_NODES = 150
SEVERITY_ORDER = [s.value for s in Severity.ordered()]
EVIDENCE_ORDER = [k.value for k in EvidenceKind]
FINDING_COLUMNS = [
    "id",
    "severity",
    "score",
    "title",
    "principal",
    "resource",
    "confidence",
    "evidence kind",
]
IDENTITY_COLUMNS = ["principal", "max severity", "findings", "highest score"]
EXPORTS: tuple[tuple[str, str, str, str], ...] = (
    ("json", "Download JSON", "attackpath-report.json", "application/json"),
    ("markdown", "Download Markdown", "attackpath-report.md", "text/markdown"),
    ("html", "Download HTML", "attackpath-report.html", "text/html"),
)
GRAPH_LEGEND = (
    "Red nodes are admin-equivalent identities, amber nodes are high-sensitivity resources; "
    "dashed edges carry less than high confidence."
)


# ---------------------------------------------------------------------------
# input and analysis
# ---------------------------------------------------------------------------


def input_path_from(argv: Sequence[str], environ: Mapping[str, str]) -> Path | None:
    """Return ``--input`` from the script arguments, else ``ATTACKPATH_INPUT``, else None."""
    args = list(argv[1:])
    for index, arg in enumerate(args):
        if arg == "--input" and index + 1 < len(args):
            return Path(args[index + 1])
        if arg.startswith("--input="):
            return Path(arg.partition("=")[2])
    value = environ.get(INPUT_ENV_VAR, "").strip()
    return Path(value) if value else None


@st.cache_data(show_spinner="Analyzing snapshot...")
def analyze_snapshot(path: str, mtime_ns: int) -> tuple[AnalysisReport, AttackGraph]:
    """Load and analyze the snapshot at ``path``.

    ``mtime_ns`` is part of the cache key only: editing the file and rerunning the page
    triggers a fresh analysis instead of serving the cached result.
    """
    loaded = load_input(Path(path))
    result = analyze(loaded.environment, mode=loaded.mode, input_warnings=loaded.warnings)
    return build_report(result, loaded.description), result.graph


@st.cache_data(show_spinner=False)
def render_export(path: str, mtime_ns: int, fmt: str) -> str:
    """Render the cached report in ``fmt`` with the renderers the CLI uses."""
    report, _graph = analyze_snapshot(path, mtime_ns)
    return render(report, fmt)


def load_or_stop() -> tuple[Path, int, AnalysisReport, AttackGraph]:
    """Resolve and analyze the input, or stop the script with an error message."""
    input_path = input_path_from(sys.argv, os.environ)
    if input_path is None:
        st.error(
            "No snapshot given. Start the dashboard with "
            "`attackpath dashboard --input <snapshot.json>` or set ATTACKPATH_INPUT."
        )
        st.stop()
    resolved = input_path.resolve()
    if not resolved.is_file():
        st.error(f"Input file not found: `{resolved}`")
        st.stop()
    mtime_ns = resolved.stat().st_mtime_ns
    try:
        report, graph = analyze_snapshot(str(resolved), mtime_ns)
    except AttackPathError as exc:
        st.error(f"Could not analyze the snapshot: {exc}")
        st.stop()
    return resolved, mtime_ns, report, graph


# ---------------------------------------------------------------------------
# filters
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Filters:
    """Sidebar selection; empty sequences and empty strings match everything."""

    severities: tuple[str, ...]
    categories: tuple[str, ...]
    checks: tuple[str, ...]
    evidence_kinds: tuple[str, ...]
    principal: str
    resource: str

    def matches(self, finding: Finding) -> bool:
        return (
            (not self.severities or finding.severity.value in self.severities)
            and (not self.categories or finding.category.value in self.categories)
            and (not self.checks or finding.check_id in self.checks)
            and (not self.evidence_kinds or finding.evidence_kind.value in self.evidence_kinds)
            and self.principal in (finding.affected_principal or "").lower()
            and self.resource in (finding.affected_resource or "").lower()
        )


def render_sidebar(report: AnalysisReport, path: Path) -> Filters:
    """Draw the filter controls and the run summary; return the active filters."""
    findings = report.findings
    present_severities = {f.severity.value for f in findings}
    present_kinds = {f.evidence_kind.value for f in findings}
    with st.sidebar:
        st.header("Filters")
        st.caption(
            "Empty selections match everything; text filters are case-insensitive substrings."
        )
        severities = st.multiselect(
            "Severity", [s for s in SEVERITY_ORDER if s in present_severities]
        )
        categories = st.multiselect("Category", sorted({f.category.value for f in findings}))
        checks = st.multiselect("Check id", sorted({f.check_id for f in findings}))
        kinds = st.multiselect("Evidence kind", [k for k in EVIDENCE_ORDER if k in present_kinds])
        principal = st.text_input("Principal contains", placeholder="name or ARN fragment")
        resource = st.text_input("Resource contains", placeholder="name or ARN fragment")
        st.divider()
        st.header("Run")
        label = "synthetic" if report.synthetic else report.source
        st.text(
            f"file: {path}\n"
            f"environment: {report.environment_name} ({label})\n"
            f"account: {report.account_id}\n"
            f"generated: {report.generated_at}\n"
            f"analysis: {report.analysis_seconds or 0.0:.3f} s\n"
            f"tool: {report.tool_version}"
        )
        st.caption(
            "Results are cached per file modification time: edit the snapshot and rerun the "
            "page (press R) to re-analyze."
        )
    return Filters(
        severities=tuple(severities),
        categories=tuple(categories),
        checks=tuple(checks),
        evidence_kinds=tuple(kinds),
        principal=principal.strip().lower(),
        resource=resource.strip().lower(),
    )


# ---------------------------------------------------------------------------
# overview
# ---------------------------------------------------------------------------


def render_header(report: AnalysisReport) -> None:
    st.title("AWS Cloud Attack Path Analyzer")
    st.caption(f"Offline IAM posture analysis of `{report.input_description}`.")
    if report.synthetic:
        st.info(
            "Synthetic data: this dashboard was generated from a synthetic fixture, not real "
            "account data. " + SYNTHETIC_NOTICE
        )
    st.warning(
        "Scores are prioritization heuristics, not proof of exploitability. " + HEURISTIC_NOTICE
    )


def severity_frame(counts: Mapping[str, int]) -> pd.DataFrame:
    """Counts per severity with an ordered categorical axis so the chart keeps rank order."""
    return pd.DataFrame(
        {
            "severity": pd.Categorical(list(counts), categories=SEVERITY_ORDER, ordered=True),
            "findings": list(counts.values()),
        }
    )


def identity_frame(findings: Sequence[Finding]) -> pd.DataFrame:
    """One row per affected principal: worst severity, finding count and highest score."""
    rows: dict[str, dict[str, Any]] = {}
    for finding in findings:
        principal = finding.affected_principal
        if not principal:
            continue
        row = rows.setdefault(
            principal,
            {"principal": principal, "severity": finding.severity, "findings": 0, "score": 0.0},
        )
        row["findings"] += 1
        if finding.severity.rank > row["severity"].rank:
            row["severity"] = finding.severity
        row["score"] = max(row["score"], finding.score)
    ordered = sorted(
        rows.values(),
        key=lambda r: (-r["severity"].rank, -r["score"], -r["findings"], r["principal"]),
    )
    return pd.DataFrame(
        [
            {
                "principal": r["principal"],
                "max severity": r["severity"].value,
                "findings": r["findings"],
                "highest score": r["score"],
            }
            for r in ordered
        ],
        columns=IDENTITY_COLUMNS,
    )


def render_overview(report: AnalysisReport) -> None:
    counts = report.counts_by_severity()
    columns = st.columns(len(counts) + 1)
    columns[0].metric("Total findings", len(report.findings))
    for column, (severity, count) in zip(columns[1:], counts.items(), strict=True):
        column.metric(severity.capitalize(), count)
    chart_column, table_column = st.columns([2, 3])
    with chart_column:
        st.subheader("Findings by severity")
        st.bar_chart(severity_frame(counts), x="severity", y="findings")
    with table_column:
        st.subheader("Highest-risk identities")
        st.caption("All findings, aggregated per affected principal.")
        st.dataframe(identity_frame(report.findings), hide_index=True)


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


def findings_frame(findings: Sequence[Finding]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "id": f.id,
                "severity": f.severity.value,
                "score": f.score,
                "title": f.title,
                "principal": f.affected_principal or "",
                "resource": f.affected_resource or "",
                "confidence": f.confidence.value,
                "evidence kind": f.evidence_kind.value,
            }
            for f in findings
        ],
        columns=FINDING_COLUMNS,
    )


def select_finding(findings: Sequence[Finding]) -> Finding | None:
    if not findings:
        st.info("No findings match the current filters.")
        return None
    by_id = {f.id: f for f in findings}
    chosen = st.selectbox(
        "Finding",
        list(by_id),
        format_func=lambda fid: f"{fid}  [{by_id[fid].severity.value}] {by_id[fid].title}",
    )
    return by_id[chosen]


def field(label: str, value: str) -> None:
    """A labelled value rendered without Markdown parsing."""
    left, right = st.columns([1, 6])
    left.markdown(f"**{label}**")
    right.text(value)


def item_list(label: str, items: Iterable[str], *, numbered: bool = False) -> None:
    values = list(items)
    if not values:
        return
    if numbered:
        text = "\n".join(f"{index}. {item}" for index, item in enumerate(values, start=1))
    else:
        text = "\n".join(f"- {item}" for item in values)
    field(label, text)


def path_frame(finding: Finding) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "step": index,
                "source": step.source,
                "edge": step.edge,
                "target": step.target,
                "description": step.description,
                "confidence": step.confidence.value,
                "preconditions": "; ".join(step.preconditions),
            }
            for index, step in enumerate(finding.attack_path, start=1)
        ]
    )


def render_score_breakdown(breakdown: ScoreBreakdown) -> None:
    st.markdown("**Score breakdown**")
    frame = pd.DataFrame(
        [
            {
                "factor": name,
                "value": factor.value,
                "weight": factor.weight,
                "rationale": factor.rationale,
            }
            for name, factor in breakdown.factors.items()
        ],
        columns=["factor", "value", "weight", "rationale"],
    )
    st.dataframe(frame, hide_index=True)
    cap = f"; cap applied: {breakdown.cap_applied}" if breakdown.cap_applied else ""
    st.text(
        f"base {breakdown.base_score:.1f} x evidence/confidence "
        f"{breakdown.confidence_multiplier:.2f} x preconditions "
        f"{breakdown.precondition_multiplier:.2f} = {breakdown.raw_score:.1f}; "
        f"final {breakdown.final_score:.1f}{cap}"
    )


def render_finding(finding: Finding) -> None:
    st.subheader(finding.title)
    st.caption(
        f"{finding.id} | check {finding.check_id} | {finding.category.value} | "
        f"severity {finding.severity.value} | score {finding.score:.1f} | "
        f"confidence {finding.confidence.value} | evidence {finding.evidence_kind.value}"
    )
    if finding.affected_principal:
        field("Principal", finding.affected_principal)
    if finding.affected_resource:
        field("Resource", finding.affected_resource)
    if finding.tags:
        field("Tags", ", ".join(finding.tags))
    field("Description", finding.description)
    field("Impact", finding.impact)
    item_list("Preconditions", finding.preconditions)
    if finding.evidence:
        st.markdown("**Evidence**")
        for item in finding.evidence:
            st.text(f"{item.source}: {item.detail}")
            if item.statement is not None:
                st.json(item.statement, expanded=False)
    if finding.attack_path:
        st.markdown("**Path**")
        st.dataframe(path_frame(finding), hide_index=True)
    remediation = finding.remediation
    field("Remediation", remediation.summary)
    item_list("Steps", remediation.steps, numbered=True)
    if remediation.suggested_policy is not None:
        st.markdown("**Suggested policy** (a template: validate it before use)")
        st.code(json.dumps(remediation.suggested_policy, indent=2), language="json")
    item_list("Assumptions", remediation.policy_assumptions)
    item_list("Verification", remediation.verification_steps)
    if finding.references:
        st.markdown("**References**")
        st.markdown("\n".join(f"- {url}" for url in finding.references))
    if finding.score_breakdown is not None:
        render_score_breakdown(finding.score_breakdown)


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------


def finding_node_ids(finding: Finding, graph: AttackGraph) -> list[str]:
    """Graph nodes a finding points at: its path first, then its principal and resource."""
    candidates: list[str | None] = []
    for step in finding.attack_path:
        candidates.extend((step.source, step.target))
    candidates.extend((finding.affected_principal, finding.affected_resource))
    ordered: list[str] = []
    for node_id in candidates:
        if node_id and node_id in graph.nodes and node_id not in ordered:
            ordered.append(node_id)
    return ordered


def with_neighbours(graph: AttackGraph, node_ids: Sequence[str]) -> list[str]:
    """``node_ids`` followed by every node one edge away from them."""
    ordered = list(node_ids)
    seen = set(ordered)
    for node_id in node_ids:
        for edge in graph.out_edges(node_id) + graph.in_edges(node_id):
            other = edge.target if edge.source == node_id else edge.source
            if other not in seen:
                seen.add(other)
                ordered.append(other)
    return ordered


def whole_graph_node_ids(graph: AttackGraph, findings: Sequence[Finding]) -> list[str]:
    """Every node, those referenced by findings first so that a capped view keeps them."""
    ordered: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        for node_id in finding_node_ids(finding, graph):
            if node_id not in seen:
                seen.add(node_id)
                ordered.append(node_id)
    ordered.extend(node_id for node_id in sorted(graph.nodes) if node_id not in seen)
    return ordered


def render_graph(graph: AttackGraph, report: AnalysisReport, finding: Finding | None) -> None:
    st.header("Permission relationships")
    whole = st.toggle(f"Show the whole graph (capped at {FULL_GRAPH_MAX_NODES} nodes)")
    if whole:
        node_ids = whole_graph_node_ids(graph, report.findings)
    elif finding is None:
        st.caption("Select a finding to see the nodes on its path.")
        return
    else:
        node_ids = finding_node_ids(finding, graph)
        if not node_ids:
            st.caption(
                "The selected finding does not point at graph nodes (it describes coverage or "
                "an evaluation limit); switch on the whole graph to browse the environment."
            )
            return
        if st.checkbox("Include directly connected nodes"):
            node_ids = with_neighbours(graph, node_ids)
    shown = node_ids[:FULL_GRAPH_MAX_NODES]
    if len(shown) < len(node_ids):
        st.caption(
            f"Showing {len(shown)} of {len(node_ids)} nodes, those referenced by findings "
            f"first. {GRAPH_LEGEND}"
        )
    else:
        st.caption(f"{len(shown)} node(s). {GRAPH_LEGEND}")
    st.graphviz_chart(graph.to_dot(node_ids=shown))


# ---------------------------------------------------------------------------
# completeness and export
# ---------------------------------------------------------------------------


def count_frame(counts: Mapping[str, int], label: str) -> pd.DataFrame:
    return pd.DataFrame(list(counts.items()), columns=[label, "count"])


def coverage_frame(services: Mapping[str, Any]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "service": name,
                "status": str(entry.get("status", "")),
                "notes": "; ".join(entry.get("notes", [])),
            }
            for name, entry in services.items()
        ],
        columns=["service", "status", "notes"],
    )


def render_completeness(report: AnalysisReport) -> None:
    st.header("Scan completeness")
    coverage_column, limits_column = st.columns(2)
    with coverage_column:
        st.markdown("**Inventory coverage**")
        services = report.coverage.get("services", {})
        if services:
            st.dataframe(coverage_frame(services), hide_index=True)
        else:
            st.text("No coverage information was declared in the snapshot.")
        notes = report.coverage.get("notes", [])
        if notes:
            st.text("\n".join(f"- {note}" for note in notes))
        if report.coverage.get("complete"):
            st.caption("The snapshot declares complete coverage of the inventoried services.")
        else:
            st.caption("Coverage is incomplete or undeclared: findings may be missing.")
    with limits_column:
        st.markdown("**Limitations and warnings**")
        if report.limitations:
            st.text("\n".join(f"- {item}" for item in report.limitations))
        else:
            st.text("None recorded for this run.")
    st.markdown("**Graph summary**")
    summary = report.graph
    metrics = st.columns(4)
    metrics[0].metric("Nodes", summary.node_count)
    metrics[1].metric("Edges", summary.edge_count)
    metrics[2].metric("Paths found", summary.paths_found)
    metrics[3].metric("Path search truncated", "yes" if summary.paths_truncated else "no")
    nodes_column, edges_column, inventory_column = st.columns(3)
    nodes_column.dataframe(count_frame(summary.nodes_by_type, "node type"), hide_index=True)
    edges_column.dataframe(count_frame(summary.edges_by_type, "edge type"), hide_index=True)
    inventory_column.dataframe(
        count_frame(report.environment_summary, "inventory"), hide_index=True
    )


def render_exports(path: str, mtime_ns: int) -> None:
    st.header("Export")
    st.caption("Rendered with the same renderers as `attackpath analyze --output`.")
    columns = st.columns(len(EXPORTS))
    for column, (fmt, label, file_name, mime) in zip(columns, EXPORTS, strict=True):
        column.download_button(
            label, data=render_export(path, mtime_ns, fmt), file_name=file_name, mime=mime
        )


# ---------------------------------------------------------------------------
# page
# ---------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(page_title="AWS Cloud Attack Path Analyzer", layout="wide")
    path, mtime_ns, report, graph = load_or_stop()
    filters = render_sidebar(report, path)
    render_header(report)
    render_overview(report)
    filtered = [f for f in report.findings if filters.matches(f)]
    st.header("Findings")
    st.caption(f"{len(filtered)} of {len(report.findings)} findings match the current filters.")
    st.dataframe(findings_frame(filtered), hide_index=True)
    st.header("Finding detail")
    selected = select_finding(filtered)
    if selected is not None:
        render_finding(selected)
    render_graph(graph, report, selected)
    render_completeness(report)
    render_exports(str(path), mtime_ns)


if __name__ == "__main__":
    main()
