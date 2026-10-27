"""Report rendering: JSON, Markdown and standalone HTML."""

from __future__ import annotations

from pathlib import Path

from attackpath.models.finding import AnalysisReport
from attackpath.reporting.html_report import render_html
from attackpath.reporting.json_report import render_json
from attackpath.reporting.markdown_report import render_markdown

FORMATS: tuple[str, ...] = ("json", "markdown", "html")
_FILENAMES = {
    "json": "attackpath-report.json",
    "markdown": "attackpath-report.md",
    "html": "attackpath-report.html",
}
_RENDERERS = {"json": render_json, "markdown": render_markdown, "html": render_html}


def render(report: AnalysisReport, fmt: str) -> str:
    if fmt not in _RENDERERS:
        raise ValueError(f"unknown report format {fmt!r}")
    return _RENDERERS[fmt](report)


def write_reports(
    report: AnalysisReport, output_dir: Path, formats: tuple[str, ...] = FORMATS
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        path = output_dir / _FILENAMES[fmt]
        path.write_text(render(report, fmt), encoding="utf-8")
        written.append(path)
    return written


__all__ = ["FORMATS", "render", "render_html", "render_json", "render_markdown", "write_reports"]
