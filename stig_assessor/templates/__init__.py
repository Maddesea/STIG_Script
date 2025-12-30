"""Template management modules.

This package contains boilerplate template management for STIG assessment
findings and compliance text templates.

Public API:
    - BP: Boilerplate template manager singleton class
    - BOILERPLATE: Module-level singleton instance
"""

from __future__ import annotations

from stig_assessor.templates.boilerplate import BP, BOILERPLATE

__all__ = [
    "BP",
    "BOILERPLATE",
]
