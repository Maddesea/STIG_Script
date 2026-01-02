"""STIG Viewer validation module.

This package provides STIG Viewer 2.18 compatibility validation logic
for CKL checklist files.

Team 5 Deliverable - Complete validation implementation.

Example:
    >>> from stig_assessor.validation import Val, validator
    >>> is_valid, errors, warnings, info = validator.validate("checklist.ckl")
    >>> if not is_valid:
    ...     print(f"Found {len(errors)} errors")
"""

from __future__ import annotations

from stig_assessor.validation.validator import Val, validator

__all__ = ["Val", "validator"]
