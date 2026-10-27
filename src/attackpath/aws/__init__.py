"""Optional, read-only AWS inventory adapter (requires the ``aws`` extra).

Importing this package never imports boto3; the ``aws-scan`` command checks for
it lazily and explains how to install the extra when it is missing.
"""

from __future__ import annotations

from attackpath.aws.inventory import AwsInventoryCollector
from attackpath.aws.safeguards import READ_ONLY_OPERATIONS, install_safeguards, read_only_policy
from attackpath.aws.scan import scan_command

__all__ = [
    "READ_ONLY_OPERATIONS",
    "AwsInventoryCollector",
    "install_safeguards",
    "read_only_policy",
    "scan_command",
]
