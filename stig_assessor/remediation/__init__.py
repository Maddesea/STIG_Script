"""Remediation processing module.

This module provides functionality for processing remediation results and
applying them to STIG checklists.
"""

from stig_assessor.remediation.models import FixResult
from stig_assessor.remediation.processor import FixResPro

__all__ = [
    "FixResult",
    "FixResPro",
]
