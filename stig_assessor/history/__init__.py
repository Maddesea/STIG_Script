"""History tracking modules.

This package contains history entry models and lifecycle management
for vulnerability history with automatic deduplication, sorting, and compression.

Public API:
    - Hist: Dataclass representing a single history entry
    - HistMgr: Manager class for history lifecycle operations
"""

from __future__ import annotations

from .models import Hist
from .manager import HistMgr

__all__ = [
    "Hist",
    "HistMgr",
]
