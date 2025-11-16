"""
History management module.

This module provides classes for managing vulnerability history entries
with automatic deduplication, sorting, and compression.

Public API:
    - Hist: Dataclass representing a single history entry
    - HistMgr: Manager class for history lifecycle operations
"""

from .models import Hist
from .manager import HistMgr

__all__ = [
    "Hist",
    "HistMgr",
]
