"""Evidence management module.

This module provides functionality for managing evidence files
associated with STIG vulnerabilities.

Team: 9 - Evidence Management

Public API:
    - EvidenceMeta: Evidence metadata dataclass
    - EvidenceMgr: Evidence lifecycle manager
    - EVIDENCE: Module-level singleton instance
"""

from stig_assessor.evidence.models import EvidenceMeta
from stig_assessor.evidence.manager import EvidenceMgr, EVIDENCE

__all__ = [
    "EvidenceMeta",
    "EvidenceMgr",
    "EVIDENCE",
]
