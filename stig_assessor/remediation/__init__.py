"""Remediation module for STIG fix extraction and processing.

This module handles extraction of remediation commands from XCCDF benchmarks
and provides multi-format export capabilities (JSON, CSV, Bash, PowerShell).

Team 8 Deliverables:
    - Fix: Dataclass representing a single remediation fix (models.py)
    - FixExt: Extractor for parsing XCCDF and generating remediation scripts (extractor.py)

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

Note: FixResPro and FixResult are Team 10 deliverables and will be added
      when Team 10 completes the processor module.
"""

from __future__ import annotations

from .models import Fix
from .extractor import FixExt

__all__ = [
    "Fix",
    "FixExt",
]
