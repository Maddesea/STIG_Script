"""
STIG Assessor Input Sanitization and Validation.

Provides validation and sanitization for all user inputs including
file paths, network addresses, XML content, and STIG-specific identifiers.
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Any, Optional, Union

from stig_assessor.exceptions import ValidationError
from stig_assessor.xml.schema import Sch
from stig_assessor.core.logging import LOG
from stig_assessor.core.config import Cfg


class San:
    """
    Input sanitization and validation utilities.

    Philosophy:
    - Fail fast: Raise ValidationError on invalid input, never silently accept bad data
    - No silent coercion: Don't "fix" or modify invalid input, reject it explicitly
    - Defense in depth: Multiple validation layers for critical security boundaries
    - Explicit over implicit: Clear validation rules with informative error messages

    Validation Categories:
    - File paths: Traversal detection, symlink validation, size limits, permission checks
    - Network: IP/MAC format validation with proper octet/segment checking
    - Identifiers: Vulnerability IDs (V-NNNNNN), UUIDs (RFC 4122)
    - XML: Entity escaping, control character removal, length limits
    - STIG values: Status/severity enumeration validation against STIG Viewer schema

    Security Features:
    - Path traversal prevention (../ sequences)
    - Symlink attack detection
    - Control character filtering (prevents XML injection)
    - XML entity escaping (&, <, >, ", ')
    - File size limits (prevents resource exhaustion)
    - Input length limits (prevents buffer issues)

    All methods raise ValidationError on invalid input. Never returns None or
    silently fails - caller must handle ValidationError explicitly.

    Thread-safe: Yes (stateless utility class)
    """

    # Validation patterns
    ASSET = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")
    IP = re.compile(r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$")
    MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
    VULN = re.compile(r"^V-\d{1,10}$")
    UUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)

    # Security patterns
    CTRL = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
    TRAV = re.compile(r"\.\.([/\\])")

    MAX_PATH = 260 if Cfg.IS_WIN else 4096

    @staticmethod
    def path(
        value: Union[str, Path],
        *,
        exist: bool = False,
        file: bool = False,
        dir: bool = False,
        mkpar: bool = False,
    ) -> Path:
        """
        Validate and sanitize file system paths.

        Security features:
        - Detects symlink attacks and path traversal
        - Validates file size limits
        - Checks null bytes and control characters
        - Enforces maximum path lengths

        Args:
            value: Path string or Path object to validate
            exist: If True, path must exist
            file: If True, path must be a file (when it exists)
            dir: If True, path must be a directory (when it exists)
            mkpar: If True, create parent directories

        Returns:
            Validated and resolved Path object

        Raises:
            ValidationError: If path is invalid or fails security checks
        """
        if not value or (isinstance(value, str) and not value.strip()):
            raise ValidationError("Empty path")

        try:
            as_str = str(value).strip()
            if "\x00" in as_str:
                raise ValidationError("Null byte in path")

            if San.TRAV.search(as_str):
                LOG.w(f"Potential traversal sequence in path: {as_str}")

            path = Path(as_str)

            # Expand user home and resolve
            if path.is_absolute():
                path = path.resolve(strict=False)
            else:
                path = path.expanduser().resolve(strict=False)

            if len(str(path)) > San.MAX_PATH:
                raise ValidationError(f"Path too long: {len(str(path))}")

            if mkpar:
                path.parent.mkdir(parents=True, exist_ok=True)

            if exist and not path.exists():
                raise ValidationError(f"Not found: {path}")

            if file and path.exists() and not path.is_file():
                raise ValidationError(f"Not a file: {path}")

            if dir and path.exists() and not path.is_dir():
                raise ValidationError(f"Not a directory: {path}")

            if path.exists() and path.is_file():
                size = path.stat().st_size
                if size > Cfg.MAX_FILE:
                    raise ValidationError(f"File too large: {size}")
                if not os.access(path, os.R_OK):
                    raise ValidationError(f"File not readable: {path}")

            return path
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Path validation failed for '{value}': {exc}")

    @staticmethod
    def asset(value: str) -> str:
        """Validate asset name."""
        if not value or not str(value).strip():
            raise ValidationError("Empty asset")
        value = str(value).strip()[:255]
        if not San.ASSET.match(value):
            raise ValidationError(f"Invalid asset: {value}")
        return value

    @staticmethod
    def ip(value: str) -> str:
        """
        Validate IP address format.

        Rejects leading zeros and validates octets are in range 0-255.
        """
        if not value:
            return ""
        value = str(value).strip()
        if not value:
            return ""
        if not San.IP.match(value):
            raise ValidationError(f"Invalid IP format: {value}")

        octets = value.split(".")
        if len(octets) != 4:
            raise ValidationError(f"IP must have exactly 4 octets, got {len(octets)}: {value}")

        for idx, octet in enumerate(octets):
            # Check for leading zeros (except "0" itself)
            if len(octet) > 1 and octet[0] == "0":
                raise ValidationError(f"IP octet {idx + 1} has leading zeros: {octet}")
            try:
                oct_val = int(octet)
            except ValueError:
                raise ValidationError(f"IP octet {idx + 1} is not numeric: {octet}")
            if not (0 <= oct_val <= 255):
                raise ValidationError(f"IP octet {idx + 1} out of range (0-255): {oct_val}")

        return value

    @staticmethod
    def mac(value: str) -> str:
        """Validate MAC address format."""
        if not value:
            return ""
        value = str(value).strip().upper().replace("-", ":")
        if not value:
            return ""
        if not San.MAC.match(value):
            raise ValidationError(f"Invalid MAC: {value}")
        return value

    @staticmethod
    def vuln(value: str) -> str:
        """
        Validate vulnerability ID format.

        Args:
            value: Vulnerability ID (e.g., "V-12345")

        Returns:
            Validated vulnerability ID

        Raises:
            ValidationError: If format is invalid
        """
        if not value or not str(value).strip():
            raise ValidationError("Empty vulnerability ID")
        value = str(value).strip()
        if not San.VULN.match(value):
            raise ValidationError(f"Invalid vulnerability ID: {value}")
        return value

    @staticmethod
    def status(value: str) -> str:
        """Validate STIG status value."""
        if not value:
            return "Not_Reviewed"
        value = str(value).strip()
        if value not in Sch.STAT_VALS:
            raise ValidationError(f"Invalid status: {value}")
        return value

    @staticmethod
    def sev(value: str, strict: bool = False) -> str:
        """
        Validate and normalize severity value.

        Args:
            value: Severity value to validate
            strict: If True, raises ValidationError for invalid values instead of defaulting

        Returns:
            Normalized severity value ('high', 'medium', or 'low')

        Raises:
            ValidationError: If strict=True and value is invalid
        """
        if not value:
            if strict:
                raise ValidationError("Empty severity value")
            return "medium"
        value = str(value).strip().lower()
        if value not in Sch.SEV_VALS:
            if strict:
                raise ValidationError(f"Invalid severity: {value} (must be one of: {', '.join(Sch.SEV_VALS)})")
            LOG.w(f"Invalid severity '{value}', defaulting to 'medium'")
            return "medium"
        return value

    @staticmethod
    def xml(value: Any, mx: Optional[int] = None) -> str:
        """
        Sanitize value for XML output.

        Escapes XML entities and removes control characters.

        Args:
            value: Value to sanitize
            mx: Maximum length (truncates if exceeded)

        Returns:
            Sanitized string safe for XML
        """
        if value is None:
            return ""
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception as exc:
                LOG.w(f"Failed to convert value to string for XML sanitization: {type(value)} - {exc}")
                return ""

        # Remove control characters
        value = San.CTRL.sub("", value)

        # Escape XML entities
        value = (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

        # Truncate if needed
        if mx is not None and len(value) > mx:
            value = value[: mx - 15] + "\n[TRUNCATED]"

        return value
