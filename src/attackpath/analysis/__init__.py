"""Analysis engine: runs the checks over an environment and produces findings."""

from __future__ import annotations

from attackpath.analysis.engine import AnalysisResult, analyze, build_report

__all__ = ["AnalysisResult", "analyze", "build_report"]
