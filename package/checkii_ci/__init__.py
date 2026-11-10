"""Fail-closed pull-request assessment client for the Checkii control plane.

The package is standard-library only. ``checkii_ci.cli`` is the console
entry point; ``checkii_ci.assess`` holds the assessment semantics that
``tools/aegis_ci.py`` in the platform repository used to carry.
"""

from __future__ import annotations

from checkii_ci.assess import (
    EXIT_CANCELLED,
    EXIT_ERROR,
    EXIT_PASSED,
    EXIT_POLICY_DENIED,
    EXIT_THRESHOLD,
    SEVERITY,
    TERMINAL,
    execute,
    validate,
)
from checkii_ci.client import ApiClient, ApiFailure

__version__ = "0.1.1"

__all__ = [
    "EXIT_CANCELLED",
    "EXIT_ERROR",
    "EXIT_PASSED",
    "EXIT_POLICY_DENIED",
    "EXIT_THRESHOLD",
    "SEVERITY",
    "TERMINAL",
    "ApiClient",
    "ApiFailure",
    "__version__",
    "execute",
    "validate",
]
