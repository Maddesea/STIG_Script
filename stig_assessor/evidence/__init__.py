"""Evidence management module.

This module provides functionality for managing evidence files
associated with STIG vulnerabilities.

Team: 9 - Evidence Management

Features:
    - Import evidence files with hash-based deduplication
    - Export all evidence to directory structure
    - Package evidence into ZIP archives
    - Import evidence from ZIP packages
    - Track metadata in JSON format with thread-safe operations

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
