"""History management module.

This module provides classes for managing vulnerability history entries
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
