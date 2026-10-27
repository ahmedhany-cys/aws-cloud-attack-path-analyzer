"""Exception hierarchy for the analyzer.

All errors raised on purpose derive from :class:`AttackPathError` so that the CLI
can report them without a traceback, and never include credential material.
"""

from __future__ import annotations


class AttackPathError(Exception):
    """Base class for all analyzer errors."""


class InputError(AttackPathError):
    """The input file, directory or document is invalid, unsupported or unsafe."""


class LimitExceededError(InputError):
    """A configured safety limit (file size, graph size, path count) was exceeded."""


class ConfigError(AttackPathError):
    """A configuration file (for example a scoring model) is invalid."""


class AwsScanError(AttackPathError):
    """The optional read-only AWS inventory could not be collected."""


class SafeguardViolationError(AwsScanError):
    """An AWS API operation outside the read-only allow list was attempted."""
