"""Evidence management modules.

This package contains evidence file import, export, and packaging functionality
for STIG vulnerability assessments.

Team: 9 - Evidence Management

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
