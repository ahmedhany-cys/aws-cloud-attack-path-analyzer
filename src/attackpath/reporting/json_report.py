"""JSON report: the complete, machine-readable form of the analysis."""

from __future__ import annotations

import json

from attackpath.models.finding import AnalysisReport
from attackpath.reporting.common import HEURISTIC_NOTICE, SYNTHETIC_NOTICE


def render_json(report: AnalysisReport) -> str:
    data = report.to_dict()
    notices = [HEURISTIC_NOTICE]
    if report.synthetic:
        notices.insert(0, SYNTHETIC_NOTICE)
    data = {"notices": notices, **data}
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
