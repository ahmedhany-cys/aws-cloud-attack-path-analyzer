# Contributing

Thank you for considering a contribution. This project is a security tool, so the bar for
correctness and honesty is deliberately high: a finding that overstates what the configuration
proves is a bug, and so is a missed explicit `Deny`.

## Development setup

```bash
git clone https://github.com/ahmedhany-cys/aws-cloud-attack-path-analyzer.git
cd aws-cloud-attack-path-analyzer
make install          # virtualenv + editable install with the dev extra
make check            # lint, typecheck, tests, security checks, self-check
```

No AWS account is needed for development. Everything in `make check` runs offline.

## Ground rules

* **Never weaken an evaluation to make a test pass.** If the evaluator cannot decide something,
  the correct answer is `UNKNOWN` plus a recorded limitation, not a guess.
* **Every finding needs evidence.** A check must attach the statements it relied on and set an
  honest `evidence_kind` (`observed`, `inferred`, `hypothetical`, `indeterminate`).
* **Fixtures are synthetic.** Use fictional account ids (`111111111111`, `222222222222`, ...),
  fictional names, and never paste real account data, ARNs or key material into the repository.
  Access key ids in fixtures must not look like real AWS key ids.
* **Read-only AWS access only.** Any new AWS operation must be added to the allow list in
  `src/attackpath/aws/safeguards.py`, must be read-only, and must be reflected in
  `docs/aws-setup.md`.
* **Regressions get a test.** When you fix a bug, add a test under `tests/regression/` that
  states the original symptom in its docstring.

## Adding a check

1. Create a module under `src/attackpath/analysis/checks/` exposing `CHECK_IDS` and `run(ctx)`.
2. Register it in `src/attackpath/analysis/checks/__init__.py`.
3. Produce findings through `ctx.finding(...)` so scoring, ids and serialization stay uniform.
4. Add a scenario (or extend one) in `scripts/build_scenarios.py` and an expectation in
   `src/attackpath/data/scenarios/expected.json`, then run `make scenarios`.
5. Document the check in `docs/methodology.md`.

## Pull requests

* Keep changes focused; one behaviour change per pull request.
* Run `make check` before opening the PR. CI runs the same steps on Python 3.11 to 3.14.
* Describe what the change does to findings on the sample environment (`make reports` and
  diff `reports/sample/`).

## Reporting security issues

See [SECURITY.md](SECURITY.md).
