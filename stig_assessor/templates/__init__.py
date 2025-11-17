"""Boilerplate template modules.

This package contains template management for compliance text templates
with status-aware responses.

Public API:
    - BP: Boilerplate template manager class
    - BOILERPLATE: Module-level singleton instance
"""

from __future__ import annotations

from stig_assessor.templates.boilerplate import BP, BOILERPLATE

__all__ = [
    "BP",
    "BOILERPLATE",
]
