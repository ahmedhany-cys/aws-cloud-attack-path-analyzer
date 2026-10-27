"""Standalone HTML report.

Security properties: every untrusted string is passed through :func:`html.escape`
with quotes escaped, the page carries a Content-Security-Policy that forbids
scripts and external resources, and no JavaScript is used at all.
"""

from __future__ import annotations

import json
from html import escape

from attackpath.models.finding import AnalysisReport, Finding, Severity
from attackpath.reporting.common import HEURISTIC_NOTICE, SYNTHETIC_NOTICE, group_by_severity

_CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0 auto;
       padding: 24px; color: #1f2328; background: #ffffff; max-width: 1100px; }
h1, h2, h3, h4 { line-height: 1.25; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 14px; }
th, td { border: 1px solid #d0d7de; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
pre { background: #f6f8fa; padding: 12px; overflow-x: auto; border-radius: 6px; }
.notice { border-left: 4px solid #9a6700; background: #fff8c5; padding: 8px 12px; margin: 8px 0; }
.synthetic { border-left-color: #0969da; background: #ddf4ff; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; color: #fff; }
.critical { background: #a40e26; } .high { background: #cf222e; } .medium { background: #bf8700; }
.low { background: #1a7f37; } .informational { background: #57606a; }
details { border: 1px solid #d0d7de; border-radius: 6px; padding: 8px 12px; margin: 8px 0; }
summary { cursor: pointer; font-weight: 600; }
.path li { margin: 4px 0; }
.meta { color: #57606a; font-size: 13px; }
"""


def _e(text: object) -> str:
    return escape(str(text), quote=True)


def _badge(severity: Severity) -> str:
    return f'<span class="badge {severity.value}">{_e(severity.value.upper())}</span>'


def render_html(report: AnalysisReport) -> str:
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:;\">"
    )
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<title>AWS Cloud Attack Path Analyzer report</title>")
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append("<h1>AWS Cloud Attack Path Analyzer report</h1>")
    if report.synthetic:
        parts.append(
            f'<div class="notice synthetic"><strong>Synthetic environment.</strong> {_e(SYNTHETIC_NOTICE)}</div>'
        )
    parts.append(f'<div class="notice">{_e(HEURISTIC_NOTICE)}</div>')
    parts.extend(_summary(report))
    parts.extend(_findings(report))
    parts.extend(_limitations(report))
    parts.append(
        f'<p class="meta">Scoring model source: {_e(report.scoring.get("source", "built-in"))}. Tool version {_e(report.tool_version)}.</p>'
    )
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def _summary(report: AnalysisReport) -> list[str]:
    counts = report.counts_by_severity()
    out = ["<h2>Summary</h2>", "<table>"]
    rows = [
        ("Input", report.input_description),
        (
            "Environment",
            f"{report.environment_name} ({'synthetic' if report.synthetic else report.source})",
        ),
        ("Account", report.account_id),
        ("Generated", report.generated_at),
        ("Findings", str(len(report.findings))),
    ]
    if report.analysis_seconds is not None:
        rows.append(("Analysis time", f"{report.analysis_seconds:.3f} s"))
    for key, value in rows:
        out.append(f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>")
    out.append("</table>")
    out.append("<h3>Findings by severity</h3><table><tr><th>Severity</th><th>Count</th></tr>")
    for sev in Severity.ordered():
        out.append(f"<tr><td>{_badge(sev)}</td><td>{counts[sev.value]}</td></tr>")
    out.append("</table>")
    out.append("<h3>Findings by category</h3><table><tr><th>Category</th><th>Count</th></tr>")
    for cat, count in report.counts_by_category().items():
        out.append(f"<tr><td>{_e(cat)}</td><td>{count}</td></tr>")
    out.append("</table>")
    out.append("<h3>Inventory</h3><table><tr><th>Entity</th><th>Count</th></tr>")
    for name, count in report.environment_summary.items():
        out.append(f"<tr><td>{_e(name)}</td><td>{count}</td></tr>")
    out.append("</table>")
    services = report.coverage.get("services", {})
    out.append("<h3>Coverage</h3>")
    if services:
        out.append("<table><tr><th>Service</th><th>Status</th><th>Notes</th></tr>")
        for name, entry in services.items():
            out.append(
                f"<tr><td>{_e(name)}</td><td>{_e(entry.get('status', ''))}</td><td>{_e('; '.join(entry.get('notes', [])))}</td></tr>"
            )
        out.append("</table>")
    else:
        out.append("<p>No coverage information was declared in the snapshot.</p>")
    g = report.graph
    truncated = " (truncated)" if g.paths_truncated else ""
    out.append(
        f'<p class="meta">Graph: {g.node_count} nodes, {g.edge_count} edges, '
        f"{g.paths_found} path(s){truncated}.</p>"
    )
    return out


def _findings(report: AnalysisReport) -> list[str]:
    out = ["<h2>Findings</h2>"]
    if not report.findings:
        out.append("<p>No findings.</p>")
        return out
    out.append(
        "<table><tr><th>Severity</th><th>ID</th><th>Title</th><th>Confidence</th><th>Evidence</th></tr>"
    )
    for f in report.findings:
        out.append(
            f"<tr><td>{_badge(f.severity)}</td><td><code>{_e(f.id)}</code></td><td>{_e(f.title)}</td>"
            f"<td>{_e(f.confidence.value)}</td><td>{_e(f.evidence_kind.value)}</td></tr>"
        )
    out.append("</table>")
    for sev, items in group_by_severity(report.findings).items():
        if not items:
            continue
        out.append(f"<h3>{_badge(sev)} ({len(items)})</h3>")
        for f in items:
            out.extend(_finding(f))
    return out


def _finding(f: Finding) -> list[str]:
    out = [
        f"<details><summary>{_badge(f.severity)} {_e(f.title)} <code>{_e(f.id)}</code></summary>"
    ]
    out.append("<table>")
    rows = [
        ("Check", f.check_id),
        ("Category", f.category.value),
        ("Score", f"{f.score:.1f}"),
        ("Confidence", f.confidence.value),
        ("Evidence kind", f.evidence_kind.value),
    ]
    if f.affected_principal:
        rows.append(("Principal", f.affected_principal))
    if f.affected_resource:
        rows.append(("Resource", f.affected_resource))
    if f.tags:
        rows.append(("Tags", ", ".join(f.tags)))
    for key, value in rows:
        out.append(f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>")
    out.append("</table>")
    out.append(f"<p><strong>Description.</strong> {_e(f.description)}</p>")
    out.append(f"<p><strong>Impact.</strong> {_e(f.impact)}</p>")
    if f.preconditions:
        out.append("<p><strong>Preconditions</strong></p><ul>")
        out.extend(f"<li>{_e(p)}</li>" for p in f.preconditions)
        out.append("</ul>")
    if f.evidence:
        out.append("<p><strong>Evidence</strong></p><ul>")
        for ev in f.evidence:
            out.append(f"<li><code>{_e(ev.source)}</code>: {_e(ev.detail)}")
            if ev.statement is not None:
                out.append(f"<pre>{_e(json.dumps(ev.statement, indent=2))}</pre>")
            out.append("</li>")
        out.append("</ul>")
    if f.attack_path:
        out.append('<p><strong>Path</strong></p><ol class="path">')
        for step in f.attack_path:
            out.append(
                f"<li><code>{_e(step.source)}</code> &rarr; <em>{_e(step.description)}</em> "
                f"&rarr; <code>{_e(step.target)}</code> (confidence {_e(step.confidence.value)})</li>"
            )
        out.append("</ol>")
    if f.score_breakdown:
        b = f.score_breakdown
        out.append(
            "<details><summary>Score breakdown</summary><table><tr><th>Factor</th><th>Value</th><th>Weight</th><th>Rationale</th></tr>"
        )
        for name, factor in b.factors.items():
            out.append(
                f"<tr><td>{_e(name)}</td><td>{factor.value:.2f}</td><td>{factor.weight:g}</td><td>{_e(factor.rationale)}</td></tr>"
            )
        out.append("</table>")
        cap = f" ; {_e(b.cap_applied)}" if b.cap_applied else ""
        out.append(
            f'<p class="meta">base {b.base_score:.1f} &times; evidence/confidence '
            f"{b.confidence_multiplier:.2f} &times; preconditions {b.precondition_multiplier:.2f} "
            f"= {b.raw_score:.1f}{cap}</p></details>"
        )
    r = f.remediation
    out.append(f"<p><strong>Remediation.</strong> {_e(r.summary)}</p>")
    if r.steps:
        out.append("<ol>")
        out.extend(f"<li>{_e(s)}</li>" for s in r.steps)
        out.append("</ol>")
    if r.suggested_policy is not None:
        out.append("<p>Suggested policy (template, validate before use):</p>")
        out.append(f"<pre>{_e(json.dumps(r.suggested_policy, indent=2))}</pre>")
    if r.policy_assumptions:
        out.append("<p>Assumptions:</p><ul>")
        out.extend(f"<li>{_e(a)}</li>" for a in r.policy_assumptions)
        out.append("</ul>")
    if r.verification_steps:
        out.append("<p>Verification:</p><ul>")
        out.extend(f"<li>{_e(v)}</li>" for v in r.verification_steps)
        out.append("</ul>")
    if f.references:
        out.append("<p>References:</p><ul>")
        out.extend(f"<li>{_e(u)}</li>" for u in f.references)
        out.append("</ul>")
    out.append("</details>")
    return out


def _limitations(report: AnalysisReport) -> list[str]:
    out = ["<h2>Limitations and warnings</h2>"]
    if report.limitations:
        out.append("<ul>")
        out.extend(f"<li>{_e(item)}</li>" for item in report.limitations)
        out.append("</ul>")
    else:
        out.append("<p>None recorded for this run.</p>")
    return out
