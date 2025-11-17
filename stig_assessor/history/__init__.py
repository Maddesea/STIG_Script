"""History management modules.

This package contains history entry models and lifecycle management
with automatic deduplication, sorting, and compression.

Public API:
    - Hist: Dataclass representing a single history entry
    - HistMgr: Manager class for history lifecycle operations
"""

from __future__ import annotations

from stig_assessor.history.models import Hist
from stig_assessor.history.manager import HistMgr

__all__ = [
    "Hist",
    "HistMgr",
]
