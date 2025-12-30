"""Evidence management modules.

This package provides functionality for managing evidence files
associated with STIG vulnerabilities, including import, export, and packaging.

Public API:
    - EvidenceMeta: Evidence metadata dataclass
    - EvidenceMgr: Evidence lifecycle manager
    - EVIDENCE: Module-level singleton instance
"""

from __future__ import annotations

from stig_assessor.evidence.models import EvidenceMeta
from stig_assessor.evidence.manager import EvidenceMgr, EVIDENCE

__all__ = [
    "EvidenceMeta",
    "EvidenceMgr",
    "EVIDENCE",
]
