# Developer workflow for the AWS Cloud Attack Path Analyzer.
# Every target runs locally and offline; nothing here touches an AWS account.

PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin
SAMPLE := fixtures/sample_environment.json

.PHONY: help venv install install-all lint format typecheck test test-fast security secrets \
        selfcheck reports scenarios check all dashboard clean uninstall

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

venv: ## Create the virtual environment
	test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --quiet --upgrade pip

install: venv ## Install the analyzer with development tools (offline core + boto3 for tests)
	$(BIN)/pip install --quiet -e ".[dev]"

install-all: venv ## Install every optional extra (aws, dashboard, dev)
	$(BIN)/pip install --quiet -e ".[aws,dashboard,dev]"

format: ## Format source and tests
	$(BIN)/ruff format src tests scripts

lint: ## Lint (ruff) and verify formatting
	$(BIN)/ruff check src tests scripts
	$(BIN)/ruff format --check src tests scripts

typecheck: ## Strict static typing (mypy)
	$(BIN)/mypy src

test: ## Full test suite with coverage
	$(BIN)/python -m pytest --cov=attackpath --cov-report=term-missing

test-fast: ## Test suite without coverage
	$(BIN)/python -m pytest -q

security: ## Static security analysis and dependency audit
	$(BIN)/bandit -q -r src -c pyproject.toml
	$(BIN)/pip-audit --progress-spinner off --skip-editable

secrets: ## Scan the working tree for secrets
	$(BIN)/detect-secrets scan --all-files --exclude-files '\.venv/.*|\.git/.*|.*_cache/.*|reports/dev/.*' --baseline .secrets.baseline

selfcheck: ## Run the built-in scenario self-check
	$(BIN)/python -m attackpath validate

scenarios: ## Regenerate the per-scenario fixtures from the sample environment
	$(BIN)/python scripts/build_scenarios.py

reports: ## Regenerate the committed sample reports from the synthetic fixture
	$(BIN)/python -m attackpath analyze --input $(SAMPLE) --output reports/sample --quiet
	$(BIN)/python scripts/generate_scenario_docs.py

demo: ## Re-record the terminal demo (needs asciinema and agg on PATH; never run in CI)
	PYTHON=$(BIN)/python asciinema rec --command "bash scripts/demo.sh" --overwrite docs/images/demo.cast
	agg --cols 112 --rows 36 --font-size 15 --theme asciinema docs/images/demo.cast docs/images/demo.gif

check: lint typecheck test security selfcheck ## Everything CI runs

all: install check ## Install and run every check

dashboard: ## Launch the optional local dashboard on the synthetic fixture
	$(BIN)/python -m attackpath dashboard --input $(SAMPLE)

clean: ## Remove caches and build artifacts
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .hypothesis .coverage htmlcov reports/dev
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +

uninstall: ## Remove the package from the virtual environment
	$(BIN)/pip uninstall -y aws-cloud-attack-path-analyzer
