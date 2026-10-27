# Security policy

## Scope

This repository contains an offline analysis tool. It parses configuration files that may come
from untrusted sources and, optionally, calls read-only AWS APIs with credentials the operator
selects explicitly. Security-relevant defects therefore include:

* input handling that could crash the process or exhaust memory on a crafted snapshot;
* report rendering that could inject script or markup from snapshot content;
* any code path that could perform a non-read-only AWS operation;
* any leak of credentials, tokens or account data into logs, reports or error messages;
* evaluator bugs that make the tool report a permission as safe when the configuration grants it
  (false negatives on explicit `Deny`, boundaries or conditions are treated as security bugs).

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability
reporting on this repository ("Report a vulnerability" under the Security tab). Include the
input that triggers the problem (synthetic data only) and the version or commit you tested.

You can expect an acknowledgement within a few days. Fixes are published as a new version with a
note in `CHANGELOG.md`.

## Design safeguards

The protections the tool relies on are described in [docs/security.md](docs/security.md) and
[docs/threat-model.md](docs/threat-model.md). In short: no runtime dependencies for the offline
analyzer, strict input validation with size and depth limits, escaped HTML and Markdown output with a
restrictive Content-Security-Policy, a botocore-level allow list that blocks any AWS operation
outside the documented read-only set, and no telemetry or outbound network traffic in offline mode.
