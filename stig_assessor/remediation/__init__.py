"""Remediation module for STIG fix extraction and processing.

This module handles extraction of remediation commands from XCCDF benchmarks
and provides multi-format export capabilities (JSON, CSV, Bash, PowerShell).

Key Components:
    - Fix: Dataclass representing a single remediation fix
    - FixExt: Extractor for parsing XCCDF and generating remediation scripts
    - FixResult: Remediation execution result dataclass
    - FixResPro: Remediation results processor for bulk import

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

from __future__ import annotations

from .models import Fix, FixResult
from .extractor import FixExt
from .processor import FixResPro

__all__ = [
    "Fix",
    "FixExt",
    "FixResult",
    "FixResPro",
]
