"""Documentation that quotes code must stay identical to the code."""

from __future__ import annotations

import json
import re

from attackpath.analysis.checks import ALL_CHECK_IDS
from attackpath.aws import read_only_policy
from tests.conftest import ROOT


def test_aws_setup_policy_matches_code() -> None:
    text = (ROOT / "docs" / "aws-setup.md").read_text("utf-8")
    match = re.search(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert match is not None, "docs/aws-setup.md must contain the policy as a json block"
    assert json.loads(match.group(1)) == read_only_policy()
    assert match.group(1) == json.dumps(read_only_policy(), indent=2)


def test_methodology_documents_every_check() -> None:
    text = (ROOT / "docs" / "methodology.md").read_text("utf-8")
    missing = [check_id for check_id in ALL_CHECK_IDS if f"`{check_id}`" not in text]
    assert missing == [], f"undocumented checks: {missing}"


def test_readme_commands_exist_in_cli() -> None:
    from attackpath.cli import build_parser

    parser = build_parser()
    subcommands = set(parser._subparsers._group_actions[0].choices)  # type: ignore[union-attr]
    readme = (ROOT / "README.md").read_text("utf-8")
    for command in ("analyze", "validate", "version", "aws-scan", "dashboard"):
        assert command in subcommands
        assert f"python -m attackpath {command}" in readme
