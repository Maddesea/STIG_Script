"""
Exception classes for STIG Assessor.

NOTE: This is a minimal stub for Team 7 testing.
Full implementation will be provided by TEAM 0.
"""


class STIGError(Exception):
    """Base exception for STIG operations."""
    pass


class ValidationError(STIGError):
    """Validation error."""
    pass


class FileError(STIGError):
    """File operation error."""
    pass


class ParseError(STIGError):
    """XML parsing error."""
    pass
"""Custom exceptions for STIG Assessor.

All exceptions in the application inherit from STIGError base class
to provide consistent error handling and context propagation.
"""STIG Assessor exceptions module.

This module defines all custom exception classes for the STIG Assessor application.

All exceptions inherit from STIGError, which provides context tracking for
better error diagnostics and debugging.
"""

from __future__ import annotations
from typing import Any, Dict, Optional


class STIGError(Exception):
    """Base exception with context.

    All STIG Assessor exceptions inherit from this class, which provides
    contextual information about where and why the error occurred.

    Attributes:
        msg: The error message
        ctx: Optional dictionary of contextual information (e.g., file paths, VIDs)
    """
"""Custom exception classes for STIG Assessor."""

from __future__ import annotations
from typing import Optional, Dict, Any


class STIGError(Exception):
    """Base exception with context."""

    def __init__(self, msg: str, ctx: Optional[Dict[str, Any]] = None):
        super().__init__(msg)
        self.msg = msg
        self.ctx = ctx or {}

    def __str__(self) -> str:
        if self.ctx:
            ctx_str = ", ".join(f"{k}={v}" for k, v in self.ctx.items())
            return f"{self.msg} [{ctx_str}]"
        return self.msg


class ValidationError(STIGError):
    """Raised when validation fails (STIG Viewer compatibility)."""


class FileError(STIGError):
    """Raised when file operations fail."""


class ParseError(STIGError):
    """Raised when XML parsing fails."""
    """Validation failure."""


class FileError(STIGError):
    """File operation failure."""


class ParseError(STIGError):
    """Parsing failure."""
