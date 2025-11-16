"""
STIG Assessor Exception Classes.

All custom exceptions for the STIG Assessor application.
Provides structured error handling with context support.
"""

from __future__ import annotations
from typing import Any, Dict, Optional


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
    """Validation failure."""


class FileError(STIGError):
    """File operation failure."""


class ParseError(STIGError):
    """Parsing failure."""
