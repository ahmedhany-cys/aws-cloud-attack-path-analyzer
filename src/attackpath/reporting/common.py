"""Shared helpers for the report renderers."""

from __future__ import annotations

from attackpath.models.finding import AnalysisReport, Finding, PathStep, Severity

SYNTHETIC_NOTICE = (
    "This report was generated from a synthetic fixture. The identities, accounts and resources are "
    "fictional; nothing in it describes a real AWS account."
)
HEURISTIC_NOTICE = (
    "Scores and severities are prioritization heuristics derived from configuration, not proof that "
    "an action succeeds in a live account. Findings marked hypothetical or indeterminate depend on "
    "context the snapshot does not contain."
)


def md_escape(text: str) -> str:
    """Escape untrusted text for Markdown tables and inline use (no raw HTML, no table breaks)."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def md_code(text: str) -> str:
    """Inline code span that cannot be broken out of."""
    safe = (
        str(text)
        .replace("`", "'")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )
    return f"`{safe}`"


def severity_badge(severity: Severity) -> str:
    return severity.value.upper()


def group_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    groups: dict[Severity, list[Finding]] = {s: [] for s in Severity.ordered()}
    for finding in findings:
        groups[finding.severity].append(finding)
    return groups


def mermaid_path(steps: list[PathStep]) -> str:
    """Render a path as a Mermaid flowchart with sanitized ids and quoted labels."""
    if not steps:
        return ""
    lines = ["flowchart LR"]
    ids: dict[str, str] = {}

    def node(name: str) -> str:
        if name not in ids:
            ids[name] = f"n{len(ids)}"
            lines.append(f'    {ids[name]}["{_mermaid_label(name)}"]')
        return ids[name]

    for step in steps:
        src = node(step.source)
        dst = node(step.target)
        lines.append(f'    {src} -- "{_mermaid_label(step.description)}" --> {dst}')
    return "\n".join(lines)


def _mermaid_label(text: str) -> str:
    return (
        str(text)
        .replace("#", "#35;")
        .replace('"', "#quot;")
        .replace("<", "#lt;")
        .replace(">", "#gt;")
        .replace("\n", " ")
    )


def top_findings(report: AnalysisReport, limit: int = 10) -> list[Finding]:
    return report.findings[:limit]
