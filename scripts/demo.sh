#!/usr/bin/env bash
# Scripted terminal session behind docs/images/demo.cast and demo.gif (see `make demo`).
#
# Every command below really runs against the synthetic fixture; nothing is pre-rendered.
# The prompt lines are typed out slowly so the recording is readable, and the pauses give
# the viewer time to read each output. Requires the project to be installed in the active
# environment (`pip install -e ".[dev]"`).

set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON=${PYTHON:-python}

type_command() {
    printf '\033[1;32m$\033[0m '
    local text="$*"
    local i
    for ((i = 0; i < ${#text}; i++)); do
        printf '%s' "${text:i:1}"
        sleep 0.025
    done
    printf '\n'
    sleep 0.6
}

pause() { sleep "${1:-1.5}"; }

type_command "python -m attackpath version"
"$PYTHON" -m attackpath version
pause 1.5

type_command "python -m attackpath validate"
"$PYTHON" -m attackpath validate
pause 3

type_command "python -m attackpath analyze --input fixtures/sample_environment.json --output reports/demo/"
"$PYTHON" -m attackpath analyze --input fixtures/sample_environment.json --output reports/demo/
pause 4

type_command "python -m attackpath analyze --input fixtures/sample_environment.json --format markdown --min-severity critical --quiet | head -n 26"
"$PYTHON" -m attackpath analyze --input fixtures/sample_environment.json --format markdown --min-severity critical --quiet | head -n 26
pause 5

type_command "python -m attackpath analyze --input fixtures/iam_policies/ --format json --quiet | python -c \"import json, sys; print(json.load(sys.stdin)['summary'])\""
"$PYTHON" -m attackpath analyze --input fixtures/iam_policies/ --format json --quiet | "$PYTHON" -c "import json, sys; print(json.load(sys.stdin)['summary'])"
pause 4
