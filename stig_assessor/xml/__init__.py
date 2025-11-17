"""XML processing modules.

Provides XML schema definitions, sanitization, and utilities.
"""

# Exports will be added when xml modules are created
This package contains XML schema definitions, sanitization, and utility functions
for processing STIG XCCDF and CKL files.
"""

from __future__ import annotations

from stig_assessor.xml.schema import Sch
from stig_assessor.xml.sanitizer import San

__all__ = [
    "Sch",
    "San",
]
"""XML processing modules."""

from __future__ import annotations

__all__ = []
