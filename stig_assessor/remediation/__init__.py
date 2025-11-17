"""
Remediation module for STIG fix extraction and processing.

This module handles extraction of remediation commands from XCCDF benchmarks
and provides multi-format export capabilities (JSON, CSV, Bash, PowerShell).

Key Components:
    - Fix: Dataclass representing a single remediation fix
    - FixExt: Extractor for parsing XCCDF and generating remediation scripts

Usage:
    from stig_assessor.remediation import Fix, FixExt

    # Extract fixes from XCCDF
    extractor = FixExt("/path/to/benchmark.xml")
    fixes = extractor.extract()

    # Export to various formats
    extractor.to_json("fixes.json")
    extractor.to_csv("fixes.csv")
    extractor.to_bash("remediate.sh", dry_run=True)
    extractor.to_powershell("Remediate.ps1", dry_run=True)
"""

from .models import Fix
from .extractor import FixExt

__all__ = [
    "Fix",
    "FixExt",
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
"""Remediation module.

Provides fix extraction and remediation results processing.
"""

# Exports will be added when remediation modules are created
"""Remediation modules.

This package contains remediation fix extraction, processing, and results import.
"""
"""Remediation and fix management modules."""

from __future__ import annotations

__all__ = []
