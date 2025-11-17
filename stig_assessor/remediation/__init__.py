"""Remediation module for STIG fix extraction and processing.

This module handles extraction of remediation commands from XCCDF benchmarks
and provides multi-format export capabilities (JSON, CSV, Bash, PowerShell).
It also handles processing of remediation results and applying them to CKL
checklists.

Key Components:
    - Fix: Dataclass representing a single remediation fix
    - FixResult: Dataclass representing a remediation execution result
    - FixExt: Extractor for parsing XCCDF and generating remediation scripts
    - FixResPro: Processor for applying remediation results to checklists

Usage:
    from stig_assessor.remediation import Fix, FixExt, FixResult, FixResPro

    # Extract fixes from XCCDF
    extractor = FixExt("/path/to/benchmark.xml")
    fixes = extractor.extract()

    # Export to various formats
    extractor.to_json("fixes.json")
    extractor.to_csv("fixes.csv")
    extractor.to_bash("remediate.sh", dry_run=True)
    extractor.to_powershell("Remediate.ps1", dry_run=True)

    # Process remediation results
    processor = FixResPro()
    processor.load("results.json")
    processor.update_ckl("checklist.ckl", "updated.ckl")
"""

from __future__ import annotations

from stig_assessor.remediation.models import Fix, FixResult
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro

__all__ = [
    "Fix",
    "FixResult",
    "FixExt",
    "FixResPro",
]
