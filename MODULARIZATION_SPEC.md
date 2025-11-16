# STIG Assessor Modularization - Technical Specification
**Version:** 1.0
**Date:** 2025-11-16
**Author:** Claude (Anthropic)
**Target Version:** 8.0.0

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [Package Structure](#package-structure)
4. [Module Specifications](#module-specifications)
   - [Level 1: Foundation](#level-1-foundation)
   - [Level 2: Core Infrastructure](#level-2-core-infrastructure)
   - [Level 3: XML Processing](#level-3-xml-processing)
   - [Level 4: I/O Operations](#level-4-io-operations)
   - [Level 5: Business Logic](#level-5-business-logic)
   - [Level 6: Integration Layer](#level-6-integration-layer)
   - [Level 7: User Interface](#level-7-user-interface)
5. [Interface Contracts](#interface-contracts)
6. [Migration Strategy](#migration-strategy)
7. [Testing Requirements](#testing-requirements)

---

## Overview

This specification defines the modularization of STIG_Script.py (~6000 lines) into a maintainable, testable package structure while preserving:

- **Zero runtime dependencies** (stdlib only)
- **Air-gap certification** (no network calls)
- **Backward compatibility** (existing scripts continue to work)
- **STIG Viewer 2.18 compliance**
- **Thread safety** (where applicable)

### Goals

1. Enable parallel development by multiple teams
2. Improve testability (unit + integration tests)
3. Reduce cognitive load (smaller, focused modules)
4. Maintain single-file distribution option
5. Facilitate future enhancements

---

## Architecture Principles

### Dependency Rules

- **Acyclic dependencies**: No circular imports
- **Layer isolation**: Higher levels depend on lower levels only
- **Explicit interfaces**: Public APIs documented with type hints
- **Minimal coupling**: Modules interact through well-defined contracts

### Import Strategy

```python
# Always use absolute imports
from stig_assessor.core.constants import VERSION, Status
from stig_assessor.exceptions import ValidationError

# Never use relative imports for cross-module
# Only use relative imports within same subpackage
from .models import Hist  # OK within stig_assessor/history/
```

### Threading & Concurrency

- **Thread-safe modules**: GlobalState, Log, FO (atomic writes)
- **Thread-unsafe modules**: Everything else (document assumptions)
- **Synchronization**: Use threading.Lock where needed
- **Documentation**: Mark thread-safety in docstrings

---

## Package Structure

```
stig_assessor/
├── __init__.py                 # Package metadata, version export
├── __main__.py                 # CLI entry point (python -m stig_assessor)
├── exceptions.py               # All exception classes
├── core/                       # Core infrastructure
│   ├── __init__.py
│   ├── constants.py            # Constants, enums
│   ├── state.py                # GlobalState singleton
│   ├── deps.py                 # Dependency detection
│   ├── config.py               # Cfg configuration
│   └── logging.py              # Log system
├── xml/                        # XML processing
│   ├── __init__.py
│   ├── schema.py               # Sch namespace definitions
│   ├── sanitizer.py            # San sanitization
│   └── utils.py                # XmlUtils utilities
├── io/                         # File operations
│   ├── __init__.py
│   └── file_ops.py             # FO atomic writes/backups
├── validation/                 # STIG Viewer validation
│   ├── __init__.py
│   └── validator.py            # Val validation logic
├── history/                    # History tracking
│   ├── __init__.py
│   ├── models.py               # Hist dataclass
│   └── manager.py              # HistMgr lifecycle
├── templates/                  # Boilerplate templates
│   ├── __init__.py
│   └── boilerplate.py          # BP template management
├── processor/                  # Main processor
│   ├── __init__.py
│   └── processor.py            # Proc XCCDF/CKL operations
├── remediation/                # Remediation system
│   ├── __init__.py
│   ├── models.py               # Fix, FixResult dataclasses
│   ├── extractor.py            # FixExt extraction
│   └── processor.py            # FixResPro bulk import
├── evidence/                   # Evidence management
│   ├── __init__.py
│   ├── models.py               # EvidenceMeta dataclass
│   └── manager.py              # EvidenceMgr operations
└── ui/                         # User interfaces
    ├── __init__.py
    ├── cli.py                  # CLI argument parsing
    ├── gui.py                  # GUI (tkinter)
    └── presets.py              # PresetMgr
```

---

## Module Specifications

---

## Level 1: Foundation

### 1.1 exceptions.py

**Purpose**: Define all custom exception classes for the application.

**Source Lines**: 276-299

**Dependencies**: None

**Public API**:

```python
class STIGError(Exception):
    """Base exception for all STIG Assessor errors."""
    pass

class ValidationError(STIGError):
    """Raised when validation fails (STIG Viewer compatibility)."""
    pass

class FileError(STIGError):
    """Raised when file operations fail."""
    pass

class ParseError(STIGError):
    """Raised when XML parsing fails."""
    pass
```

**Usage Example**:

```python
from stig_assessor.exceptions import ValidationError

if not Status.is_valid(status):
    raise ValidationError(f"Invalid status: {status}")
```

**Testing Requirements**:
- Verify inheritance chain (STIGError → Exception)
- Test exception message propagation
- Verify picklability (for multiprocessing, future)

---

### 1.2 core/constants.py

**Purpose**: Define all application constants, enumerations, and configuration values.

**Source Lines**: 66-181

**Dependencies**: None

**Public API**:

```python
from enum import Enum
from typing import FrozenSet

# Version info
VERSION: str = "8.0.0"
BUILD_DATE: str = "2025-11-16"
APP_NAME: str = "STIG Assessor Complete"
STIG_VIEWER_VERSION: str = "2.18"

# File handling
LARGE_FILE_THRESHOLD: int = 50 * 1024 * 1024  # 50MB
CHUNK_SIZE: int = 8192
MAX_RETRIES: int = 3
RETRY_DELAY: float = 0.5
MAX_XML_SIZE: int = 500 * 1024 * 1024  # 500MB

# Encodings
ENCODINGS: list[str] = [
    "utf-8", "utf-8-sig", "utf-16", "utf-16-le",
    "utf-16-be", "latin-1", "cp1252", "iso-8859-1", "ascii"
]

# Limits
MAX_FILE_SIZE: int = 500 * 1024 * 1024
MAX_HISTORY_ENTRIES: int = 200
MAX_FINDING_LENGTH: int = 65_000
MAX_COMMENT_LENGTH: int = 32_000
MAX_MERGE_FILES: int = 100
MAX_VULNERABILITIES: int = 15_000
KEEP_BACKUPS: int = 30
KEEP_LOGS: int = 15

# Error thresholds
ERROR_THRESHOLD: float = 0.25  # Fail if >25% errors

# Deduplication
DEDUP_WINDOW: int = 20  # History entries to check
COMPRESSION_THRESHOLD: int = 1024  # Bytes before compression

class Status(str, Enum):
    """STIG finding status values (STIG Viewer compatible)."""
    NOT_A_FINDING = "NotAFinding"
    OPEN = "Open"
    NOT_REVIEWED = "Not_Reviewed"
    NOT_APPLICABLE = "Not_Applicable"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if status value is valid."""
        return value in cls._value2member_map_

    @classmethod
    def all_values(cls) -> FrozenSet[str]:
        """Return all valid status values."""
        return frozenset(m.value for m in cls)

class Severity(str, Enum):
    """STIG severity levels (CAT I/II/III)."""
    HIGH = "high"      # CAT I
    MEDIUM = "medium"  # CAT II
    LOW = "low"        # CAT III

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if severity value is valid."""
        return value in cls._value2member_map_

    @classmethod
    def all_values(cls) -> FrozenSet[str]:
        """Return all valid severity values."""
        return frozenset(m.value for m in cls)
```

**Usage Example**:

```python
from stig_assessor.core.constants import Status, VERSION, MAX_FILE_SIZE

if Status.is_valid(user_input):
    print(f"Valid status: {user_input}")
```

**Testing Requirements**:
- Verify all enum values are strings
- Test `is_valid()` with valid/invalid inputs
- Test `all_values()` returns complete set
- Verify constants have expected types

**Migration Notes**:
- No behavioral changes from original
- Just reorganization into dedicated module

---

## Level 2: Core Infrastructure

### 2.1 core/state.py

**Purpose**: Process-wide shutdown coordination and resource management (singleton).

**Source Lines**: 188-275

**Dependencies**:
- `stig_assessor.core.constants`
- `stig_assessor.exceptions`

**Public API**:

```python
from typing import Callable, Set, List
from pathlib import Path
import threading
import signal
import atexit

class GlobalState:
    """
    Process-wide shutdown coordinator and resource manager (Singleton).

    Thread-safe: Yes
    """

    _instance: Optional['GlobalState'] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> 'GlobalState':
        """Singleton implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize shutdown coordinator."""
        if hasattr(self, '_initialized'):
            return
        self._shutdown_flag: bool = False
        self._cleanup_callbacks: List[Callable[[], None]] = []
        self._temp_files: Set[Path] = set()
        self._temp_lock: threading.Lock = threading.Lock()
        self._initialized = True

        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        atexit.register(self.cleanup)

    def shutdown(self) -> None:
        """Signal graceful shutdown."""
        self._shutdown_flag = True

    def is_shutdown(self) -> bool:
        """Check if shutdown initiated."""
        return self._shutdown_flag

    def add_temp(self, path: Path) -> None:
        """Track temporary file for cleanup."""
        with self._temp_lock:
            self._temp_files.add(path)

    def remove_temp(self, path: Path) -> None:
        """Untrack temporary file."""
        with self._temp_lock:
            self._temp_files.discard(path)

    def register_cleanup(self, callback: Callable[[], None]) -> None:
        """Register cleanup callback."""
        self._cleanup_callbacks.append(callback)

    def cleanup(self) -> None:
        """Execute all cleanup operations."""
        # Run callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception:
                pass

        # Clean temp files
        with self._temp_lock:
            for path in self._temp_files:
                try:
                    if path.exists():
                        path.unlink()
                except Exception:
                    pass
            self._temp_files.clear()

    def _handle_signal(self, signum: int, frame) -> None:
        """Handle termination signals."""
        self.shutdown()
        self.cleanup()
        sys.exit(0)

# Module-level singleton instance
GLOBAL_STATE = GlobalState()
```

**Usage Example**:

```python
from stig_assessor.core.state import GLOBAL_STATE

# Track temporary file
temp = Path("/tmp/work.xml")
GLOBAL_STATE.add_temp(temp)

# Register cleanup
GLOBAL_STATE.register_cleanup(lambda: print("Shutting down"))

# Check shutdown
if GLOBAL_STATE.is_shutdown():
    return
```

**Testing Requirements**:
- Test singleton behavior (multiple instantiations return same object)
- Test thread-safety of temp file tracking
- Test signal handling (SIGINT, SIGTERM)
- Test cleanup execution order
- Mock file operations for cleanup testing

**Thread Safety**: Full (uses locks for all mutable state)

---

### 2.2 core/deps.py

**Purpose**: Detect optional dependencies (tkinter, defusedxml).

**Source Lines**: 344-428

**Dependencies**:
- `stig_assessor.core.logging` (circular - use lazy import)

**Public API**:

```python
from typing import Optional

class Deps:
    """
    Dependency detection for optional components.

    Thread-safe: Yes (no mutable state)
    """

    @staticmethod
    def has_tkinter() -> bool:
        """Check if tkinter is available."""
        try:
            import tkinter
            return True
        except ImportError:
            return False

    @staticmethod
    def has_defusedxml() -> bool:
        """Check if defusedxml is available."""
        try:
            import defusedxml.ElementTree
            return True
        except ImportError:
            return False

    @staticmethod
    def get_xml_parser() -> tuple[Any, str]:
        """
        Get best available XML parser.

        Returns:
            (parser_module, parser_name)
        """
        if Deps.has_defusedxml():
            import defusedxml.ElementTree as ET
            return ET, "defusedxml"
        else:
            import xml.etree.ElementTree as ET
            return ET, "stdlib"

    @staticmethod
    def check_large_file_parser(file_size: int) -> None:
        """
        Validate parser capabilities for large files.

        Args:
            file_size: File size in bytes

        Raises:
            RuntimeError: If file too large for available parser
        """
        from stig_assessor.core.constants import LARGE_FILE_THRESHOLD
        from stig_assessor.exceptions import FileError

        if file_size > LARGE_FILE_THRESHOLD:
            if not Deps.has_defusedxml():
                raise FileError(
                    f"File size {file_size} bytes exceeds threshold. "
                    f"Install defusedxml for large file support."
                )
```

**Usage Example**:

```python
from stig_assessor.core.deps import Deps

if Deps.has_tkinter():
    from stig_assessor.ui.gui import GUI
    app = GUI()
else:
    print("GUI not available (tkinter missing)")

# Get parser
parser, name = Deps.get_xml_parser()
tree = parser.parse(path)
```

**Testing Requirements**:
- Test with tkinter available/unavailable (mock import)
- Test with defusedxml available/unavailable
- Test parser selection logic
- Test large file validation

**Thread Safety**: Yes (stateless)

---

### 2.3 core/config.py

**Purpose**: Application configuration and directory management.

**Source Lines**: 429-601

**Dependencies**:
- `stig_assessor.core.constants`
- `stig_assessor.core.state`
- `stig_assessor.exceptions`

**Public API**:

```python
from pathlib import Path
from typing import Optional
import os

class Cfg:
    """
    Application configuration and directory manager (Singleton).

    Thread-safe: No (initialize once at startup)
    """

    _instance: Optional['Cfg'] = None

    def __new__(cls) -> 'Cfg':
        """Singleton implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration."""
        if hasattr(self, '_initialized'):
            return

        self.home: Path = self._find_home()
        self.app_dir: Path = self.home / ".stig_assessor"
        self.log_dir: Path = self.app_dir / "logs"
        self.backup_dir: Path = self.app_dir / "backups"
        self.evidence_dir: Path = self.app_dir / "evidence"
        self.template_dir: Path = self.app_dir / "templates"
        self.preset_dir: Path = self.app_dir / "presets"
        self.fix_dir: Path = self.app_dir / "fixes"
        self.export_dir: Path = self.app_dir / "exports"

        self._ensure_directories()
        self._initialized = True

    def _find_home(self) -> Path:
        """
        Find writable home directory.

        Priority:
        1. Path.home()
        2. $USERPROFILE or $HOME
        3. $TMPDIR/stig_user
        4. $CWD/.stig_home

        Returns:
            Writable home directory path

        Raises:
            FileError: If no writable directory found
        """
        # Try Path.home()
        try:
            home = Path.home()
            if self._is_writable(home):
                return home
        except Exception:
            pass

        # Try environment variables
        for var in ["USERPROFILE", "HOME"]:
            if var in os.environ:
                home = Path(os.environ[var])
                if self._is_writable(home):
                    return home

        # Try temp directory
        import tempfile
        temp = Path(tempfile.gettempdir()) / "stig_user"
        if self._is_writable(temp.parent):
            temp.mkdir(exist_ok=True)
            return temp

        # Last resort: current directory
        cwd = Path.cwd() / ".stig_home"
        if self._is_writable(cwd.parent):
            cwd.mkdir(exist_ok=True)
            return cwd

        raise FileError("Cannot find writable home directory")

    def _is_writable(self, path: Path) -> bool:
        """Test if directory is writable."""
        try:
            test_file = path / f".write_test_{os.getpid()}"
            test_file.touch()
            test_file.unlink()
            return True
        except Exception:
            return False

    def _ensure_directories(self) -> None:
        """Create all required directories."""
        for dir_path in [
            self.app_dir, self.log_dir, self.backup_dir,
            self.evidence_dir, self.template_dir, self.preset_dir,
            self.fix_dir, self.export_dir
        ]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def cleanup_old(self) -> dict[str, int]:
        """
        Clean old backups and logs.

        Returns:
            Dictionary with cleanup statistics
        """
        from stig_assessor.core.constants import KEEP_BACKUPS, KEEP_LOGS

        stats = {"backups_removed": 0, "logs_removed": 0}

        # Clean backups
        backups = sorted(
            self.backup_dir.glob("*.bak"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        for backup in backups[KEEP_BACKUPS:]:
            try:
                backup.unlink()
                stats["backups_removed"] += 1
            except Exception:
                pass

        # Clean logs
        logs = sorted(
            self.log_dir.glob("*.log*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        for log in logs[KEEP_LOGS:]:
            try:
                log.unlink()
                stats["logs_removed"] += 1
            except Exception:
                pass

        return stats

# Module-level singleton
CFG = Cfg()
```

**Usage Example**:

```python
from stig_assessor.core.config import CFG

# Access directories
log_path = CFG.log_dir / "app.log"
backup_path = CFG.backup_dir / "file.bak"

# Cleanup old files
stats = CFG.cleanup_old()
print(f"Removed {stats['backups_removed']} old backups")
```

**Testing Requirements**:
- Test home directory detection (mock environment)
- Test directory creation
- Test writable check
- Test cleanup logic
- Test fallback behavior

**Thread Safety**: No (initialize at startup only)

---

### 2.4 core/logging.py

**Purpose**: Thread-safe structured logging with context.

**Source Lines**: 602-704

**Dependencies**:
- `stig_assessor.core.constants`
- `stig_assessor.core.config`

**Public API**:

```python
import logging
import logging.handlers
from typing import Optional
import threading
from pathlib import Path

class Log:
    """
    Thread-safe structured logging system (Singleton).

    Thread-safe: Yes
    """

    _instance: Optional['Log'] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> 'Log':
        """Singleton implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize logging system."""
        if hasattr(self, '_initialized'):
            return

        from stig_assessor.core.config import CFG

        self.logger = logging.getLogger("stig_assessor")
        self.logger.setLevel(logging.DEBUG)

        # Rotating file handler (10MB, 5 backups)
        log_file = CFG.log_dir / "stig_assessor.log"
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )

        # Format: 2025-11-16 10:30:45.123 [INFO] [Thread-1] Message
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d [%(levelname)s] [%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Console handler (optional)
        self._console_handler: Optional[logging.Handler] = None
        self._initialized = True

    def set_verbose(self, verbose: bool = True) -> None:
        """Enable/disable console output."""
        if verbose and not self._console_handler:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("[%(levelname)s] %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self._console_handler = handler
        elif not verbose and self._console_handler:
            self.logger.removeHandler(self._console_handler)
            self._console_handler = None

    def debug(self, msg: str, **kwargs) -> None:
        """Log debug message with context."""
        self.logger.debug(self._format(msg, kwargs))

    def info(self, msg: str, **kwargs) -> None:
        """Log info message with context."""
        self.logger.info(self._format(msg, kwargs))

    def warning(self, msg: str, **kwargs) -> None:
        """Log warning message with context."""
        self.logger.warning(self._format(msg, kwargs))

    def error(self, msg: str, **kwargs) -> None:
        """Log error message with context."""
        self.logger.error(self._format(msg, kwargs))

    def critical(self, msg: str, **kwargs) -> None:
        """Log critical message with context."""
        self.logger.critical(self._format(msg, kwargs))

    def _format(self, msg: str, context: dict) -> str:
        """Format message with context."""
        if not context:
            return msg
        ctx_str = " ".join(f"{k}={v}" for k, v in context.items())
        return f"{msg} | {ctx_str}"

# Module-level singleton
LOG = Log()
```

**Usage Example**:

```python
from stig_assessor.core.logging import LOG

LOG.info("Processing vulnerabilities", count=150, file="test.ckl")
LOG.error("Parse failed", vid="V-12345", line=42)
LOG.set_verbose(True)  # Enable console output
```

**Testing Requirements**:
- Test file rotation
- Test thread-safety (concurrent logging)
- Test verbose mode toggle
- Test message formatting with context
- Verify log file creation

**Thread Safety**: Yes (logging module is thread-safe)

---

## Level 3: XML Processing

### 3.1 xml/schema.py

**Purpose**: XML namespace definitions and schema constants.

**Source Lines**: 705-812

**Dependencies**:
- `stig_assessor.core.constants`

**Public API**:

```python
from typing import Dict, Optional

class Sch:
    """
    XML schema definitions for STIG/CKL formats.

    Thread-safe: Yes (immutable constants)
    """

    # Namespaces
    NS: Dict[str, str] = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "dc": "http://purl.org/dc/elements/1.1/",
        "cdf": "http://checklists.nist.gov/xccdf/1.1",
    }

    # CKL Root elements
    CHECKLIST_ROOT = "CHECKLIST"
    ASSET = "ASSET"
    STIGS = "STIGS"
    ISTIG = "iSTIG"
    STIG_INFO = "STIG_INFO"
    VULN = "VULN"

    # Asset elements
    ROLE = "ROLE"
    ASSET_TYPE = "ASSET_TYPE"
    HOST_NAME = "HOST_NAME"
    HOST_IP = "HOST_IP"
    HOST_MAC = "HOST_MAC"
    HOST_FQDN = "HOST_FQDN"
    TECH_AREA = "TECH_AREA"
    TARGET_KEY = "TARGET_KEY"
    WEB_OR_DATABASE = "WEB_OR_DATABASE"
    WEB_DB_SITE = "WEB_DB_SITE"
    WEB_DB_INSTANCE = "WEB_DB_INSTANCE"

    # STIG_INFO elements
    SI_DATA = "SI_DATA"
    SID_NAME = "SID_NAME"
    SID_DATA = "SID_DATA"

    # VULN elements
    STIG_DATA = "STIG_DATA"
    VULN_ATTRIBUTE = "VULN_ATTRIBUTE"
    ATTRIBUTE_DATA = "ATTRIBUTE_DATA"
    STATUS = "STATUS"
    FINDING_DETAILS = "FINDING_DETAILS"
    COMMENTS = "COMMENTS"
    SEVERITY_OVERRIDE = "SEVERITY_OVERRIDE"
    SEVERITY_JUSTIFICATION = "SEVERITY_JUSTIFICATION"

    # XCCDF elements (with namespace)
    XCCDF_BENCHMARK = "Benchmark"
    XCCDF_GROUP = "Group"
    XCCDF_RULE = "Rule"
    XCCDF_VERSION = "version"
    XCCDF_TITLE = "title"
    XCCDF_DESCRIPTION = "description"
    XCCDF_REFERENCE = "reference"
    XCCDF_FIXTEXT = "fixtext"
    XCCDF_FIX = "fix"
    XCCDF_CHECK = "check"
    XCCDF_CHECK_CONTENT = "check-content"

    # Required VULN_ATTRIBUTE names
    REQUIRED_ATTRS = [
        "Vuln_Num",
        "Severity",
        "Group_Title",
        "Rule_ID",
        "Rule_Ver",
        "Rule_Title",
        "Vuln_Discuss",
        "IA_Controls",
        "Check_Content",
        "Fix_Text",
        "False_Positives",
        "False_Negatives",
        "Documentable",
        "Mitigations",
        "Potential_Impact",
        "Third_Party_Tools",
        "Mitigation_Control",
        "Responsibility",
        "Security_Override_Guidance",
        "CCI_REF",
    ]

    @staticmethod
    def ns(tag: str, namespace: str = "xccdf") -> str:
        """
        Get namespaced tag.

        Args:
            tag: Element tag name
            namespace: Namespace prefix (default: xccdf)

        Returns:
            Fully qualified tag name
        """
        if namespace in Sch.NS:
            return f"{{{Sch.NS[namespace]}}}{tag}"
        return tag

    @staticmethod
    def strip_ns(tag: str) -> str:
        """
        Remove namespace from tag.

        Args:
            tag: Potentially namespaced tag

        Returns:
            Tag without namespace
        """
        if '}' in tag:
            return tag.split('}', 1)[1]
        return tag
```

**Usage Example**:

```python
from stig_assessor.xml.schema import Sch

# Find elements with namespace
benchmark = root.find(Sch.ns("Benchmark"))
groups = root.findall(f".//{Sch.ns('Group')}")

# Access constants
status_elem = vuln.find(Sch.STATUS)
required_fields = Sch.REQUIRED_ATTRS
```

**Testing Requirements**:
- Test namespace resolution
- Test tag stripping
- Verify all constants are strings
- Test with/without namespace

**Thread Safety**: Yes (immutable data)

---

### 3.2 xml/sanitizer.py

**Purpose**: XML sanitization and input validation.

**Source Lines**: 961-1229

**Dependencies**:
- `stig_assessor.core.constants`
- `stig_assessor.core.logging`

**Public API**:

```python
from typing import Optional, Any
import re

class San:
    """
    XML sanitization and validation utilities.

    Thread-safe: Yes (stateless)
    """

    # Dangerous XML characters
    XML_ESCAPE = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&apos;',
    }

    # Regex for dangerous patterns
    DANGEROUS_PATTERN = re.compile(r'[<>&"\']')

    @staticmethod
    def txt(value: Any, default: str = "", max_len: Optional[int] = None) -> str:
        """
        Sanitize text for XML.

        Args:
            value: Input value (any type)
            default: Default if value is None/empty
            max_len: Maximum length (truncate if exceeded)

        Returns:
            Sanitized string safe for XML
        """
        # Handle None
        if value is None:
            return default

        # Convert to string
        if not isinstance(value, str):
            value = str(value)

        # Strip whitespace
        value = value.strip()
        if not value:
            return default

        # Escape dangerous characters
        value = San._escape_xml(value)

        # Truncate if needed
        if max_len and len(value) > max_len:
            value = value[:max_len] + "..."

        return value

    @staticmethod
    def xml_safe(value: str) -> str:
        """
        Escape XML special characters.

        Args:
            value: Input string

        Returns:
            XML-safe string
        """
        return San._escape_xml(value)

    @staticmethod
    def _escape_xml(text: str) -> str:
        """Replace dangerous XML characters."""
        for char, escape in San.XML_ESCAPE.items():
            text = text.replace(char, escape)
        return text

    @staticmethod
    def trunc(text: str, max_len: int, suffix: str = "...") -> str:
        """
        Truncate text with suffix.

        Args:
            text: Input text
            max_len: Maximum length
            suffix: Truncation indicator

        Returns:
            Truncated text
        """
        if len(text) <= max_len:
            return text
        return text[:max_len - len(suffix)] + suffix

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validate IPv4 address.

        Args:
            ip: IP address string

        Returns:
            True if valid IPv4
        """
        pattern = re.compile(
            r'^(?:'
            r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'
            r'){3}'
            r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
        )
        return bool(pattern.match(ip))

    @staticmethod
    def validate_mac(mac: str) -> bool:
        """
        Validate MAC address.

        Args:
            mac: MAC address string

        Returns:
            True if valid MAC
        """
        pattern = re.compile(
            r'^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
        )
        return bool(pattern.match(mac))

    @staticmethod
    def normalize_status(status: str) -> str:
        """
        Normalize status value to STIG Viewer format.

        Args:
            status: Input status

        Returns:
            Normalized status
        """
        from stig_assessor.core.constants import Status

        # Try exact match
        if Status.is_valid(status):
            return status

        # Try case-insensitive match
        status_lower = status.lower()
        for valid_status in Status.all_values():
            if valid_status.lower() == status_lower:
                return valid_status

        # Default
        return Status.NOT_REVIEWED.value

    @staticmethod
    def normalize_severity(severity: str, strict: bool = False) -> str:
        """
        Normalize severity value.

        Args:
            severity: Input severity
            strict: If True, raise error on invalid; if False, default to medium

        Returns:
            Normalized severity

        Raises:
            ValidationError: If strict=True and invalid
        """
        from stig_assessor.core.constants import Severity
        from stig_assessor.exceptions import ValidationError

        # Try exact match
        if Severity.is_valid(severity):
            return severity

        # Try case-insensitive
        severity_lower = severity.lower()
        for valid_sev in Severity.all_values():
            if valid_sev.lower() == severity_lower:
                return valid_sev

        # Map CAT values
        cat_map = {
            "cat i": Severity.HIGH.value,
            "cat 1": Severity.HIGH.value,
            "cat ii": Severity.MEDIUM.value,
            "cat 2": Severity.MEDIUM.value,
            "cat iii": Severity.LOW.value,
            "cat 3": Severity.LOW.value,
        }
        if severity_lower in cat_map:
            return cat_map[severity_lower]

        if strict:
            raise ValidationError(f"Invalid severity: {severity}")

        return Severity.MEDIUM.value
```

**Usage Example**:

```python
from stig_assessor.xml.sanitizer import San

# Sanitize user input
safe_text = San.txt(user_input, default="N/A", max_len=1000)

# Validate addresses
if San.validate_ip("192.168.1.1"):
    print("Valid IP")

# Normalize values
status = San.normalize_status("open")  # Returns "Open"
severity = San.normalize_severity("CAT I")  # Returns "high"
```

**Testing Requirements**:
- Test XML escaping (all dangerous characters)
- Test truncation logic
- Test IP validation (valid/invalid, edge cases like 192.001.001.001)
- Test MAC validation
- Test status/severity normalization
- Test strict mode for severity

**Thread Safety**: Yes (stateless)

---

### 3.3 xml/utils.py

**Purpose**: XML utility functions for common operations.

**Source Lines**: 813-960

**Dependencies**:
- `stig_assessor.xml.schema`
- `stig_assessor.xml.sanitizer`
- `stig_assessor.core.logging`

**Public API**:

```python
from typing import Optional, Dict, Any
from xml.etree.ElementTree import Element

class XmlUtils:
    """
    XML utility functions for STIG/CKL processing.

    Thread-safe: Yes (stateless)
    """

    @staticmethod
    def get_text(elem: Optional[Element], default: str = "") -> str:
        """
        Get element text safely.

        Args:
            elem: XML element
            default: Default if element is None or has no text

        Returns:
            Element text or default
        """
        if elem is None:
            return default
        return (elem.text or "").strip() or default

    @staticmethod
    def set_text(elem: Element, text: str, sanitize: bool = True) -> None:
        """
        Set element text safely.

        Args:
            elem: XML element
            text: Text to set
            sanitize: Apply XML sanitization
        """
        from stig_assessor.xml.sanitizer import San

        if sanitize:
            text = San.txt(text)
        elem.text = text

    @staticmethod
    def get_attrib(elem: Element, key: str, default: str = "") -> str:
        """
        Get element attribute safely.

        Args:
            elem: XML element
            key: Attribute name
            default: Default if attribute missing

        Returns:
            Attribute value or default
        """
        return elem.get(key, default)

    @staticmethod
    def find_stig_data(vuln: Element, attr_name: str) -> Optional[str]:
        """
        Find STIG_DATA value by VULN_ATTRIBUTE name.

        Args:
            vuln: VULN element
            attr_name: VULN_ATTRIBUTE value to find

        Returns:
            ATTRIBUTE_DATA text or None
        """
        from stig_assessor.xml.schema import Sch

        for sdata in vuln.findall(Sch.STIG_DATA):
            vattr = sdata.find(Sch.VULN_ATTRIBUTE)
            if vattr is not None and vattr.text == attr_name:
                adata = sdata.find(Sch.ATTRIBUTE_DATA)
                return XmlUtils.get_text(adata)
        return None

    @staticmethod
    def set_stig_data(vuln: Element, attr_name: str, value: str) -> None:
        """
        Set STIG_DATA value by VULN_ATTRIBUTE name.

        Args:
            vuln: VULN element
            attr_name: VULN_ATTRIBUTE name
            value: Value to set
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.sanitizer import San
        import xml.etree.ElementTree as ET

        # Find existing
        for sdata in vuln.findall(Sch.STIG_DATA):
            vattr = sdata.find(Sch.VULN_ATTRIBUTE)
            if vattr is not None and vattr.text == attr_name:
                adata = sdata.find(Sch.ATTRIBUTE_DATA)
                if adata is None:
                    adata = ET.SubElement(sdata, Sch.ATTRIBUTE_DATA)
                adata.text = San.txt(value)
                return

        # Create new
        sdata = ET.SubElement(vuln, Sch.STIG_DATA)
        vattr = ET.SubElement(sdata, Sch.VULN_ATTRIBUTE)
        vattr.text = attr_name
        adata = ET.SubElement(sdata, Sch.ATTRIBUTE_DATA)
        adata.text = San.txt(value)

    @staticmethod
    def get_vid(vuln: Element) -> Optional[str]:
        """
        Extract Vuln_Num from VULN element.

        Args:
            vuln: VULN element

        Returns:
            Vulnerability ID (e.g., V-12345) or None
        """
        return XmlUtils.find_stig_data(vuln, "Vuln_Num")

    @staticmethod
    def create_element(tag: str, text: str = "", attrib: Optional[Dict[str, str]] = None) -> Element:
        """
        Create XML element with text and attributes.

        Args:
            tag: Element tag name
            text: Element text
            attrib: Element attributes

        Returns:
            New XML element
        """
        import xml.etree.ElementTree as ET
        from stig_assessor.xml.sanitizer import San

        elem = ET.Element(tag, attrib or {})
        if text:
            elem.text = San.txt(text)
        return elem
```

**Usage Example**:

```python
from stig_assessor.xml.utils import XmlUtils

# Safe text extraction
title = XmlUtils.get_text(elem, default="Untitled")

# STIG_DATA operations
vid = XmlUtils.get_vid(vuln_elem)
severity = XmlUtils.find_stig_data(vuln_elem, "Severity")
XmlUtils.set_stig_data(vuln_elem, "Severity", "high")

# Create elements
elem = XmlUtils.create_element("STATUS", "Open")
```

**Testing Requirements**:
- Test get_text with None/empty elements
- Test find_stig_data with missing attributes
- Test set_stig_data (create new vs update existing)
- Test get_vid with valid/invalid VULN elements
- Test sanitization in set operations

**Thread Safety**: Yes (stateless)

---

## Level 4: I/O Operations

### 4.1 io/file_ops.py

**Purpose**: Atomic file operations with backups and encoding detection.

**Source Lines**: 1230-1475

**Dependencies**:
- `stig_assessor.core.constants`
- `stig_assessor.core.config`
- `stig_assessor.core.logging`
- `stig_assessor.core.state`
- `stig_assessor.exceptions`

**Public API**:

```python
from pathlib import Path
from typing import Optional, Union, BinaryIO
import xml.etree.ElementTree as ET
from contextlib import contextmanager

class FO:
    """
    File operations with atomicity, backups, and encoding detection.

    Thread-safe: Partial (atomic_write has retry logic)
    """

    @staticmethod
    def read_with_fallback(path: Path, sample_size: int = 8192) -> str:
        """
        Read file with encoding detection.

        Args:
            path: File path
            sample_size: Bytes to sample for detection

        Returns:
            File contents as string

        Raises:
            FileError: If file unreadable
        """
        from stig_assessor.core.constants import ENCODINGS
        from stig_assessor.exceptions import FileError

        # Try each encoding
        for encoding in ENCODINGS:
            try:
                with path.open('r', encoding=encoding) as f:
                    return f.read()
            except (UnicodeDecodeError, LookupError):
                continue

        raise FileError(f"Cannot decode file: {path}")

    @staticmethod
    def atomic_write(
        path: Path,
        content: Union[str, bytes],
        backup: bool = True,
        encoding: str = "utf-8"
    ) -> None:
        """
        Atomic file write with optional backup.

        Args:
            path: Target file path
            content: Content to write
            backup: Create .bak file
            encoding: Text encoding (for str content)

        Raises:
            FileError: If write fails
        """
        from stig_assessor.core.config import CFG
        from stig_assessor.core.state import GLOBAL_STATE
        from stig_assessor.core.constants import MAX_RETRIES, RETRY_DELAY
        from stig_assessor.exceptions import FileError
        import tempfile
        import time
        import os

        # Create backup if file exists
        if backup and path.exists():
            backup_path = CFG.backup_dir / f"{path.name}.{int(time.time())}.bak"
            try:
                import shutil
                shutil.copy2(path, backup_path)
            except Exception as e:
                raise FileError(f"Backup failed: {e}")

        # Write to temp file first
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=".tmp",
            prefix=path.stem + "_",
            dir=path.parent
        )
        temp_path = Path(temp_path)
        GLOBAL_STATE.add_temp(temp_path)

        try:
            # Write content
            if isinstance(content, bytes):
                with os.fdopen(temp_fd, 'wb') as f:
                    f.write(content)
            else:
                with os.fdopen(temp_fd, 'w', encoding=encoding) as f:
                    f.write(content)

            # Atomic rename with retry (Windows race condition fix)
            for attempt in range(MAX_RETRIES):
                try:
                    temp_path.replace(path)
                    GLOBAL_STATE.remove_temp(temp_path)
                    return
                except OSError as e:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY * (2 ** attempt))
                    else:
                        raise FileError(f"Atomic write failed: {e}")

        except Exception as e:
            # Cleanup on failure
            if temp_path.exists():
                temp_path.unlink()
            GLOBAL_STATE.remove_temp(temp_path)
            raise FileError(f"Write failed: {e}")

    @staticmethod
    def save_xml(tree: ET.ElementTree, path: Path, backup: bool = True) -> None:
        """
        Save XML tree atomically.

        Args:
            tree: XML ElementTree
            path: Output path
            backup: Create backup
        """
        from stig_assessor.exceptions import FileError
        import xml.etree.ElementTree as ET

        try:
            # Serialize to bytes
            xml_bytes = ET.tostring(
                tree.getroot(),
                encoding="utf-8",
                xml_declaration=True
            )

            # Atomic write
            FO.atomic_write(path, xml_bytes, backup=backup)

        except Exception as e:
            raise FileError(f"XML save failed: {e}")

    @staticmethod
    def load_xml(path: Path) -> ET.ElementTree:
        """
        Load and parse XML file.

        Args:
            path: XML file path

        Returns:
            Parsed ElementTree

        Raises:
            FileError: If file not found
            ParseError: If XML invalid
        """
        from stig_assessor.core.deps import Deps
        from stig_assessor.core.constants import MAX_XML_SIZE
        from stig_assessor.exceptions import FileError, ParseError

        if not path.exists():
            raise FileError(f"File not found: {path}")

        # Check file size
        file_size = path.stat().st_size
        if file_size > MAX_XML_SIZE:
            raise FileError(f"File too large: {file_size} bytes")

        # Check parser capabilities
        Deps.check_large_file_parser(file_size)

        # Parse
        parser, parser_name = Deps.get_xml_parser()
        try:
            tree = parser.parse(str(path))
            return tree
        except Exception as e:
            raise ParseError(f"XML parse failed: {e}")

    @staticmethod
    def validate_path(path: Path, base: Optional[Path] = None) -> Path:
        """
        Validate path for symlink attacks.

        Args:
            path: Path to validate
            base: Base directory (must be parent)

        Returns:
            Resolved absolute path

        Raises:
            FileError: If path is unsafe
        """
        from stig_assessor.exceptions import FileError

        # Resolve to absolute
        resolved = path.resolve()

        # Check base containment
        if base is not None:
            base_resolved = base.resolve()
            try:
                resolved.relative_to(base_resolved)
            except ValueError:
                raise FileError(f"Path outside base: {path}")

        return resolved

    @staticmethod
    @contextmanager
    def temp_file(suffix: str = ".tmp", prefix: str = "stig_"):
        """
        Context manager for temporary files.

        Args:
            suffix: File suffix
            prefix: File prefix

        Yields:
            Path to temporary file
        """
        import tempfile
        from stig_assessor.core.state import GLOBAL_STATE

        fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        temp_path = Path(temp_path)
        GLOBAL_STATE.add_temp(temp_path)

        try:
            import os
            os.close(fd)
            yield temp_path
        finally:
            if temp_path.exists():
                temp_path.unlink()
            GLOBAL_STATE.remove_temp(temp_path)
```

**Usage Example**:

```python
from stig_assessor.io.file_ops import FO

# Read with encoding detection
content = FO.read_with_fallback(Path("file.txt"))

# Atomic write with backup
FO.atomic_write(Path("output.ckl"), xml_content, backup=True)

# XML operations
tree = FO.load_xml(Path("input.xml"))
FO.save_xml(tree, Path("output.xml"))

# Temp file
with FO.temp_file(suffix=".xml") as temp:
    # Work with temp file
    pass  # Auto-deleted
```

**Testing Requirements**:
- Test encoding detection (all ENCODINGS)
- Test atomic write (success, failure, rollback)
- Test backup creation
- Test retry logic (mock Windows race condition)
- Test symlink validation
- Test temp file cleanup
- Test large file handling

**Thread Safety**: Partial (atomic writes use exponential backoff)

---

(Continuing with Level 5-7 modules...)

Would you like me to continue with the remaining module specifications (Validation, History, Templates, Processor, Remediation, Evidence, and UI)?## Level 5: Business Logic

### 5.1 validation/validator.py

**Purpose**: STIG Viewer 2.18 compatibility validation.

**Source Lines**: 1932-2071

**Dependencies**:
- `stig_assessor.core.constants`
- `stig_assessor.core.logging`
- `stig_assessor.xml.schema`
- `stig_assessor.xml.utils`
- `stig_assessor.xml.sanitizer`
- `stig_assessor.exceptions`

**Public API**:

```python
from xml.etree.ElementTree import ElementTree, Element
from typing import List, Dict, Any

class Val:
    """
    STIG Viewer 2.18 compatibility validation.

    Thread-safe: Yes (stateless)
    """

    @staticmethod
    def validate_ckl(tree: ElementTree, strict: bool = True) -> Dict[str, Any]:
        """
        Validate CKL file structure and content.

        Args:
            tree: CKL ElementTree
            strict: Raise errors on validation failures

        Returns:
            Validation report dict with:
                - valid: bool
                - errors: List[str]
                - warnings: List[str]
                - vuln_count: int

        Raises:
            ValidationError: If strict=True and validation fails
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils
        from stig_assessor.exceptions import ValidationError

        errors = []
        warnings = []
        root = tree.getroot()

        # Check root element
        if root.tag != Sch.CHECKLIST_ROOT:
            errors.append(f"Invalid root: {root.tag}, expected {Sch.CHECKLIST_ROOT}")

        # Check ASSET
        asset = root.find(Sch.ASSET)
        if asset is None:
            errors.append("Missing ASSET element")

        # Check STIGS
        stigs = root.find(Sch.STIGS)
        if stigs is None:
            errors.append("Missing STIGS element")
        else:
            istig = stigs.find(Sch.ISTIG)
            if istig is None:
                errors.append("Missing iSTIG element")

        # Validate vulnerabilities
        vulns = root.findall(f".//{Sch.VULN}")
        vuln_count = len(vulns)

        if vuln_count == 0:
            warnings.append("No vulnerabilities found")

        for i, vuln in enumerate(vulns):
            vuln_errors = Val._validate_vuln(vuln)
            errors.extend([f"VULN[{i}]: {e}" for e in vuln_errors])

        # Build report
        report = {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "vuln_count": vuln_count
        }

        if strict and errors:
            raise ValidationError(
                f"Validation failed with {len(errors)} errors:\n" +
                "\n".join(errors[:10])
            )

        return report

    @staticmethod
    def _validate_vuln(vuln: Element) -> List[str]:
        """
        Validate single VULN element.

        Args:
            vuln: VULN element

        Returns:
            List of error messages
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils
        from stig_assessor.core.constants import Status, Severity

        errors = []

        # Check required STIG_DATA attributes
        found_attrs = set()
        for sdata in vuln.findall(Sch.STIG_DATA):
            vattr = sdata.find(Sch.VULN_ATTRIBUTE)
            if vattr is not None and vattr.text:
                found_attrs.add(vattr.text)

        missing = set(Sch.REQUIRED_ATTRS) - found_attrs
        if missing:
            errors.append(f"Missing attributes: {missing}")

        # Check STATUS
        status_elem = vuln.find(Sch.STATUS)
        if status_elem is None:
            errors.append("Missing STATUS element")
        elif status_elem.text and not Status.is_valid(status_elem.text):
            errors.append(f"Invalid status: {status_elem.text}")

        # Check Severity
        severity = XmlUtils.find_stig_data(vuln, "Severity")
        if severity and not Severity.is_valid(severity):
            errors.append(f"Invalid severity: {severity}")

        # Check Vuln_Num
        vid = XmlUtils.get_vid(vuln)
        if not vid:
            errors.append("Missing Vuln_Num")

        return errors

    @staticmethod
    def validate_xccdf(tree: ElementTree) -> Dict[str, Any]:
        """
        Validate XCCDF benchmark file.

        Args:
            tree: XCCDF ElementTree

        Returns:
            Validation report
        """
        from stig_assessor.xml.schema import Sch

        errors = []
        warnings = []
        root = tree.getroot()

        # Check Benchmark root
        expected_tag = Sch.ns("Benchmark")
        if root.tag != expected_tag:
            errors.append(f"Invalid root: {root.tag}, expected {expected_tag}")

        # Find Groups
        groups = root.findall(f".//{Sch.ns('Group')}")
        if not groups:
            warnings.append("No Groups found")

        # Find Rules
        rules = root.findall(f".//{Sch.ns('Rule')}")
        rule_count = len(rules)

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "rule_count": rule_count,
            "group_count": len(groups)
        }

    @staticmethod
    def check_error_threshold(total: int, errors: int) -> None:
        """
        Check if error rate exceeds threshold.

        Args:
            total: Total items processed
            errors: Number of errors

        Raises:
            ValidationError: If error rate > ERROR_THRESHOLD
        """
        from stig_assessor.core.constants import ERROR_THRESHOLD
        from stig_assessor.exceptions import ValidationError

        if total == 0:
            return

        error_rate = errors / total
        if error_rate > ERROR_THRESHOLD:
            raise ValidationError(
                f"Error rate {error_rate:.1%} exceeds threshold "
                f"{ERROR_THRESHOLD:.1%} ({errors}/{total} failed)"
            )
```

**Usage Example**:

```python
from stig_assessor.validation.validator import Val
from stig_assessor.io.file_ops import FO

# Validate CKL
tree = FO.load_xml(Path("checklist.ckl"))
report = Val.validate_ckl(tree, strict=False)
print(f"Valid: {report['valid']}, Errors: {len(report['errors'])}")

# Check error threshold
Val.check_error_threshold(total=100, errors=30)  # Raises if >25%
```

**Testing Requirements**:
- Test with valid CKL files
- Test with invalid CKL (missing elements)
- Test VULN validation (all required attributes)
- Test status/severity validation
- Test error threshold logic
- Test XCCDF validation

**Thread Safety**: Yes (stateless)

---

### 5.2 history/models.py

**Purpose**: History entry dataclass.

**Source Lines**: 1476-1538

**Dependencies**:
- `stig_assessor.core.constants`

**Public API**:

```python
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

@dataclass(order=True)
class Hist:
    """
    Single history entry for a vulnerability finding.

    Thread-safe: Yes (immutable after creation)
    """

    # Sort key (newest first)
    timestamp: datetime = field(compare=True)

    # Content
    status: str = field(compare=False)
    finding: str = field(compare=False, default="")
    comments: str = field(compare=False, default="")
    username: str = field(compare=False, default="")

    def __post_init__(self):
        """Validate and normalize fields."""
        from stig_assessor.core.constants import Status
        from stig_assessor.xml.sanitizer import San

        # Ensure timezone-aware timestamp
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

        # Normalize status
        self.status = San.normalize_status(self.status)

        # Sanitize text fields
        self.finding = San.txt(self.finding, default="")
        self.comments = San.txt(self.comments, default="")
        self.username = San.txt(self.username, default="")

    def to_xml_text(self) -> str:
        """
        Serialize to XML comment format.

        Returns:
            Formatted history string for XML
        """
        timestamp_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        parts = [
            f"[{timestamp_str}]",
            f"Status: {self.status}",
        ]
        if self.username:
            parts.append(f"User: {self.username}")
        if self.finding:
            parts.append(f"Finding: {self.finding[:100]}...")
        if self.comments:
            parts.append(f"Comments: {self.comments[:100]}...")

        return " | ".join(parts)

    @staticmethod
    def from_vuln(
        vuln_elem,
        timestamp: Optional[datetime] = None
    ) -> 'Hist':
        """
        Create history entry from VULN element.

        Args:
            vuln_elem: VULN XML element
            timestamp: Override timestamp (default: now)

        Returns:
            History entry
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        status = XmlUtils.get_text(vuln_elem.find(Sch.STATUS), default="Not_Reviewed")
        finding = XmlUtils.get_text(vuln_elem.find(Sch.FINDING_DETAILS), default="")
        comments = XmlUtils.get_text(vuln_elem.find(Sch.COMMENTS), default="")

        # Extract username from comments if present
        username = ""
        # Could parse from existing history comments

        return Hist(
            timestamp=timestamp,
            status=status,
            finding=finding,
            comments=comments,
            username=username
        )

    def content_hash(self) -> str:
        """
        Generate content hash for deduplication.

        Returns:
            SHA256 hash of content fields
        """
        import hashlib

        content = f"{self.status}|{self.finding}|{self.comments}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
```

**Usage Example**:

```python
from stig_assessor.history.models import Hist
from datetime import datetime, timezone

# Create history entry
entry = Hist(
    timestamp=datetime.now(timezone.utc),
    status="Open",
    finding="Security issue detected",
    comments="Needs remediation",
    username="analyst1"
)

# Serialize
xml_text = entry.to_xml_text()

# From VULN element
entry2 = Hist.from_vuln(vuln_elem)
```

**Testing Requirements**:
- Test dataclass ordering (by timestamp)
- Test status normalization
- Test sanitization
- Test timezone handling
- Test XML serialization
- Test content hashing

**Thread Safety**: Yes (immutable)

---

### 5.3 history/manager.py

**Purpose**: History lifecycle management with deduplication.

**Source Lines**: 1539-1762

**Dependencies**:
- `stig_assessor.history.models`
- `stig_assessor.core.constants`
- `stig_assessor.core.logging`
- `stig_assessor.xml.schema`
- `stig_assessor.xml.utils`

**Public API**:

```python
from typing import List, Optional
from xml.etree.ElementTree import Element
from stig_assessor.history.models import Hist
import bisect

class HistMgr:
    """
    History lifecycle manager with deduplication and sorting.

    Thread-safe: No (single-threaded use)
    """

    def __init__(self, max_entries: int = 200):
        """
        Initialize history manager.

        Args:
            max_entries: Maximum history entries to keep
        """
        from stig_assessor.core.constants import MAX_HISTORY_ENTRIES

        self.max_entries = max_entries or MAX_HISTORY_ENTRIES
        self.entries: List[Hist] = []  # Sorted newest → oldest

    def add(self, entry: Hist, deduplicate: bool = True) -> bool:
        """
        Add history entry with deduplication.

        Args:
            entry: History entry to add
            deduplicate: Check for duplicates

        Returns:
            True if added, False if duplicate
        """
        from stig_assessor.core.logging import LOG

        # Deduplication check
        if deduplicate:
            entry_hash = entry.content_hash()
            for existing in self.entries:
                if existing.content_hash() == entry_hash:
                    LOG.debug(f"Skipping duplicate history entry: {entry_hash}")
                    return False

        # Insert sorted (bisect for O(n) vs O(n log n))
        # Entries sorted newest → oldest (reverse order)
        bisect.insort(self.entries, entry)
        self.entries.reverse()  # Maintain newest first
        self.entries = self.entries[:self.max_entries]  # Trim

        return True

    def add_from_vuln(self, vuln: Element, deduplicate: bool = True) -> bool:
        """
        Create and add entry from VULN element.

        Args:
            vuln: VULN element
            deduplicate: Check for duplicates

        Returns:
            True if added
        """
        entry = Hist.from_vuln(vuln)
        return self.add(entry, deduplicate)

    def merge(self, other: 'HistMgr', deduplicate: bool = True) -> int:
        """
        Merge another history manager.

        Args:
            other: HistMgr to merge
            deduplicate: Remove duplicates

        Returns:
            Number of entries added
        """
        added = 0
        for entry in other.entries:
            if self.add(entry, deduplicate):
                added += 1
        return added

    def to_xml_comment(self) -> str:
        """
        Serialize all entries to XML comment format.

        Returns:
            Multi-line history string
        """
        if not self.entries:
            return ""

        lines = ["=== History ==="]
        for entry in self.entries:
            lines.append(entry.to_xml_text())
        lines.append("=== End History ===")

        return "\n".join(lines)

    def parse_xml_comment(self, comment_text: str) -> int:
        """
        Parse history from XML comment text.

        Args:
            comment_text: Comment text containing history

        Returns:
            Number of entries parsed
        """
        import re
        from datetime import datetime

        count = 0
        # Match history entry pattern
        pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]\s+Status:\s+(\S+)'

        for match in re.finditer(pattern, comment_text):
            timestamp_str, status = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                # Extract more fields if present...
                entry = Hist(timestamp=timestamp, status=status)
                if self.add(entry, deduplicate=True):
                    count += 1
            except ValueError:
                continue

        return count

    def get_latest(self) -> Optional[Hist]:
        """Get most recent history entry."""
        return self.entries[0] if self.entries else None

    def get_all(self) -> List[Hist]:
        """Get all history entries (newest first)."""
        return list(self.entries)

    def clear(self) -> None:
        """Clear all history."""
        self.entries.clear()

    def __len__(self) -> int:
        """Get number of entries."""
        return len(self.entries)
```

**Usage Example**:

```python
from stig_assessor.history.manager import HistMgr
from stig_assessor.history.models import Hist

# Create manager
mgr = HistMgr(max_entries=100)

# Add entries
mgr.add_from_vuln(vuln_elem)
mgr.add(Hist(...))

# Merge histories
other_mgr = HistMgr()
added = mgr.merge(other_mgr, deduplicate=True)

# Serialize
comment_text = mgr.to_xml_comment()

# Parse
mgr2 = HistMgr()
count = mgr2.parse_xml_comment(old_comments)
```

**Testing Requirements**:
- Test bisect insertion (maintain order)
- Test deduplication logic
- Test max entries trimming
- Test merge functionality
- Test XML serialization/parsing
- Test edge cases (empty, single entry)

**Thread Safety**: No

---

### 5.4 templates/boilerplate.py

**Purpose**: Boilerplate template management.

**Source Lines**: 1763-1931

**Dependencies**:
- `stig_assessor.core.config`
- `stig_assessor.core.logging`
- `stig_assessor.io.file_ops`
- `stig_assessor.exceptions`

**Public API**:

```python
from typing import Dict, Optional
from pathlib import Path
import json

class BP:
    """
    Boilerplate template manager (Singleton).

    Thread-safe: No (load at startup)
    """

    _instance: Optional['BP'] = None

    def __new__(cls) -> 'BP':
        """Singleton implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize template manager."""
        if hasattr(self, '_initialized'):
            return

        from stig_assessor.core.config import CFG

        self.template_file: Path = CFG.template_dir / "boilerplate.json"
        self.templates: Dict[str, Dict[str, str]] = {}
        self.load()
        self._initialized = True

    def load(self) -> None:
        """Load templates from file."""
        from stig_assessor.io.file_ops import FO
        from stig_assessor.core.logging import LOG

        if not self.template_file.exists():
            LOG.info("No boilerplate file found, using defaults")
            self._load_defaults()
            self.save()
            return

        try:
            content = FO.read_with_fallback(self.template_file)
            self.templates = json.loads(content)
            LOG.info(f"Loaded {len(self.templates)} boilerplate templates")
        except Exception as e:
            LOG.error(f"Failed to load boilerplate: {e}")
            self._load_defaults()

    def save(self) -> None:
        """Save templates to file."""
        from stig_assessor.io.file_ops import FO
        from stig_assessor.exceptions import FileError

        try:
            content = json.dumps(self.templates, indent=2, ensure_ascii=False)
            FO.atomic_write(self.template_file, content, backup=False)
        except Exception as e:
            raise FileError(f"Failed to save boilerplate: {e}")

    def get(self, vid: str, status: str) -> Optional[str]:
        """
        Get boilerplate text for VID and status.

        Args:
            vid: Vulnerability ID (e.g., V-12345)
            status: Finding status

        Returns:
            Boilerplate text or None
        """
        if vid not in self.templates:
            return None
        return self.templates[vid].get(status)

    def set(self, vid: str, status: str, text: str) -> None:
        """
        Set boilerplate text.

        Args:
            vid: Vulnerability ID
            status: Finding status
            text: Boilerplate text
        """
        if vid not in self.templates:
            self.templates[vid] = {}
        self.templates[vid][status] = text

    def delete(self, vid: str, status: Optional[str] = None) -> bool:
        """
        Delete boilerplate.

        Args:
            vid: Vulnerability ID
            status: Status to delete (None = delete all for VID)

        Returns:
            True if deleted
        """
        if vid not in self.templates:
            return False

        if status is None:
            del self.templates[vid]
        elif status in self.templates[vid]:
            del self.templates[vid][status]
            if not self.templates[vid]:
                del self.templates[vid]
        else:
            return False

        return True

    def apply_to_vuln(self, vuln_elem, vid: str, status: str) -> bool:
        """
        Apply boilerplate to VULN element.

        Args:
            vuln_elem: VULN element
            vid: Vulnerability ID
            status: Current status

        Returns:
            True if boilerplate applied
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        text = self.get(vid, status)
        if text is None:
            return False

        # Apply to FINDING_DETAILS if empty
        finding_elem = vuln_elem.find(Sch.FINDING_DETAILS)
        if finding_elem is not None:
            current = XmlUtils.get_text(finding_elem)
            if not current:
                XmlUtils.set_text(finding_elem, text)
                return True

        return False

    def _load_defaults(self) -> None:
        """Load default boilerplate templates."""
        self.templates = {
            # Example defaults
            "V-*": {
                "NotAFinding": "This control is satisfied. Evidence: [describe evidence]",
                "Not_Applicable": "This control does not apply because: [justification]",
                "Open": "This control is not satisfied. Findings: [describe issue]"
            }
        }

    def list_all(self) -> Dict[str, Dict[str, str]]:
        """Get all templates."""
        return dict(self.templates)

# Module-level singleton
BOILERPLATE = BP()
```

**Usage Example**:

```python
from stig_assessor.templates.boilerplate import BOILERPLATE

# Get boilerplate
text = BOILERPLATE.get("V-12345", "NotAFinding")

# Set boilerplate
BOILERPLATE.set("V-12345", "NotAFinding", "Control satisfied via GPO")
BOILERPLATE.save()

# Apply to VULN
applied = BOILERPLATE.apply_to_vuln(vuln_elem, "V-12345", "NotAFinding")
```

**Testing Requirements**:
- Test load/save cycle
- Test get/set/delete operations
- Test apply_to_vuln logic
- Test default templates
- Test JSON serialization

**Thread Safety**: No

---

## Level 6: Integration Layer

### 6.1 processor/processor.py

**Purpose**: Main processor for XCCDF→CKL conversion and merge operations.

**Source Lines**: 2072-3303

**Dependencies**: ALL previous modules

**Public API**:

```python
from pathlib import Path
from typing import List, Dict, Any, Optional
from xml.etree.ElementTree import ElementTree, Element

class Proc:
    """
    Main processor for STIG operations.

    Thread-safe: No (creates new instance per operation)
    """

    def __init__(self):
        """Initialize processor."""
        from stig_assessor.core.logging import LOG

        self.log = LOG

    def xccdf_to_ckl(
        self,
        xccdf_path: Path,
        output_path: Path,
        asset_name: str,
        asset_ip: str = "",
        asset_mac: str = "",
        role: str = "None",
        tech_area: str = "",
        marking: str = "",
        apply_boilerplate: bool = False
    ) -> Dict[str, Any]:
        """
        Convert XCCDF benchmark to CKL checklist.

        Args:
            xccdf_path: Input XCCDF file
            output_path: Output CKL file
            asset_name: Asset hostname
            asset_ip: Asset IP address
            asset_mac: Asset MAC address
            role: Asset role
            tech_area: Technology area
            marking: Classification marking
            apply_boilerplate: Apply boilerplate templates

        Returns:
            Conversion report dict

        Raises:
            FileError: If files invalid
            ParseError: If XML invalid
            ValidationError: If conversion fails
        """
        from stig_assessor.io.file_ops import FO
        from stig_assessor.validation.validator import Val
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.sanitizer import San
        import xml.etree.ElementTree as ET

        self.log.info(f"Converting XCCDF to CKL", xccdf=xccdf_path, output=output_path)

        # Load and validate XCCDF
        xccdf_tree = FO.load_xml(xccdf_path)
        xccdf_report = Val.validate_xccdf(xccdf_tree)
        if not xccdf_report['valid']:
            raise ValidationError(f"Invalid XCCDF: {xccdf_report['errors']}")

        # Process XCCDF
        ckl_tree = self._process_xccdf(
            xccdf_tree,
            asset_name=asset_name,
            asset_ip=asset_ip,
            asset_mac=asset_mac,
            role=role,
            tech_area=tech_area,
            marking=marking,
            apply_boilerplate=apply_boilerplate
        )

        # Validate CKL
        Val.validate_ckl(ckl_tree, strict=True)

        # Save
        FO.save_xml(ckl_tree, output_path)

        self.log.info(f"Conversion complete", vulns=xccdf_report['rule_count'])

        return {
            "success": True,
            "rules_processed": xccdf_report['rule_count'],
            "output_file": str(output_path)
        }

    def _process_xccdf(
        self,
        xccdf_tree: ElementTree,
        asset_name: str,
        asset_ip: str,
        asset_mac: str,
        role: str,
        tech_area: str,
        marking: str,
        apply_boilerplate: bool
    ) -> ElementTree:
        """
        Process XCCDF to CKL structure.

        Returns:
            CKL ElementTree
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils
        from stig_assessor.xml.sanitizer import San
        import xml.etree.ElementTree as ET

        # Create CKL root
        root = ET.Element(Sch.CHECKLIST_ROOT)

        # Add ASSET
        asset = ET.SubElement(root, Sch.ASSET)
        self._populate_asset(asset, asset_name, asset_ip, asset_mac, role, tech_area, marking)

        # Add STIGS
        stigs = ET.SubElement(root, Sch.STIGS)
        istig = ET.SubElement(stigs, Sch.ISTIG)

        # Add STIG_INFO
        stig_info = ET.SubElement(istig, Sch.STIG_INFO)
        self._populate_stig_info(stig_info, xccdf_tree)

        # Process Rules → VULNs
        xccdf_root = xccdf_tree.getroot()
        groups = xccdf_root.findall(f".//{Sch.ns('Group')}")

        for group in groups:
            vuln = self._process_group(group, apply_boilerplate)
            if vuln is not None:
                istig.append(vuln)

        return ET.ElementTree(root)

    def _populate_asset(
        self,
        asset: Element,
        name: str,
        ip: str,
        mac: str,
        role: str,
        tech_area: str,
        marking: str
    ) -> None:
        """Populate ASSET element."""
        from stig_assessor.xml.utils import XmlUtils
        from stig_assessor.xml.schema import Sch
        import xml.etree.ElementTree as ET

        ET.SubElement(asset, Sch.ROLE).text = role
        ET.SubElement(asset, Sch.ASSET_TYPE).text = "Computing"
        ET.SubElement(asset, Sch.HOST_NAME).text = name
        ET.SubElement(asset, Sch.HOST_IP).text = ip
        ET.SubElement(asset, Sch.HOST_MAC).text = mac
        ET.SubElement(asset, Sch.HOST_FQDN).text = ""
        ET.SubElement(asset, Sch.TECH_AREA).text = tech_area
        ET.SubElement(asset, Sch.TARGET_KEY).text = "0"
        ET.SubElement(asset, Sch.WEB_OR_DATABASE).text = "false"

    def _populate_stig_info(self, stig_info: Element, xccdf_tree: ElementTree) -> None:
        """Populate STIG_INFO from XCCDF Benchmark."""
        # Extract metadata from XCCDF and create SI_DATA elements
        pass  # Detailed implementation...

    def _process_group(self, group: Element, apply_boilerplate: bool) -> Optional[Element]:
        """
        Process XCCDF Group to VULN element.

        Args:
            group: XCCDF Group element
            apply_boilerplate: Apply boilerplate

        Returns:
            VULN element or None if processing fails
        """
        # Extract Rule from Group
        # Create VULN with STIG_DATA
        # Apply boilerplate if requested
        pass  # Detailed implementation...

    def merge(
        self,
        base_path: Path,
        history_paths: List[Path],
        output_path: Path,
        deduplicate: bool = True
    ) -> Dict[str, Any]:
        """
        Merge multiple checklists.

        Args:
            base_path: Current/newest checklist
            history_paths: Older checklists (ordered newest → oldest)
            output_path: Output merged checklist
            deduplicate: Remove duplicate history entries

        Returns:
            Merge report dict

        Raises:
            FileError: If files invalid
            ValidationError: If merge fails
        """
        from stig_assessor.io.file_ops import FO
        from stig_assessor.validation.validator import Val
        from stig_assessor.history.manager import HistMgr
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        self.log.info(f"Merging checklists", base=base_path, histories=len(history_paths))

        # Load base
        base_tree = FO.load_xml(base_path)
        Val.validate_ckl(base_tree, strict=True)

        # Load histories
        history_trees = [FO.load_xml(p) for p in history_paths]

        # Merge each VULN
        vulns_merged = 0
        base_root = base_tree.getroot()
        base_vulns = base_root.findall(f".//{Sch.VULN}")

        for base_vuln in base_vulns:
            vid = XmlUtils.get_vid(base_vuln)
            if not vid:
                continue

            # Create history manager
            hist_mgr = HistMgr()

            # Add current state
            hist_mgr.add_from_vuln(base_vuln)

            # Merge from history files
            for hist_tree in history_trees:
                hist_root = hist_tree.getroot()
                hist_vulns = hist_root.findall(f".//{Sch.VULN}")

                for hist_vuln in hist_vulns:
                    hist_vid = XmlUtils.get_vid(hist_vuln)
                    if hist_vid == vid:
                        hist_mgr.add_from_vuln(hist_vuln, deduplicate=deduplicate)
                        break

            # Update comments with history
            comments_elem = base_vuln.find(Sch.COMMENTS)
            if comments_elem is not None:
                comments_elem.text = hist_mgr.to_xml_comment()
                vulns_merged += 1

        # Save
        FO.save_xml(base_tree, output_path)

        self.log.info(f"Merge complete", vulns=vulns_merged)

        return {
            "success": True,
            "vulns_merged": vulns_merged,
            "output_file": str(output_path)
        }

    def diff(self, old_path: Path, new_path: Path) -> Dict[str, Any]:
        """
        Compare two checklists.

        Args:
            old_path: Older checklist
            new_path: Newer checklist

        Returns:
            Diff report dict with changes
        """
        # Compare two CKL files
        # Return dict with status changes, finding changes, etc.
        pass  # Implementation...

    def repair(self, input_path: Path, output_path: Path) -> Dict[str, Any]:
        """
        Repair corrupted CKL file.

        Args:
            input_path: Corrupted CKL
            output_path: Repaired CKL

        Returns:
            Repair report
        """
        # Fix common corruption issues
        pass  # Implementation...

    def stats(self, input_path: Path, format: str = "text") -> Dict[str, Any]:
        """
        Generate compliance statistics.

        Args:
            input_path: CKL file
            format: Output format (text, json, csv)

        Returns:
            Statistics dict
        """
        # Generate compliance stats
        pass  # Implementation...
```

**Usage Example**:

```python
from stig_assessor.processor.processor import Proc
from pathlib import Path

proc = Proc()

# XCCDF → CKL
report = proc.xccdf_to_ckl(
    xccdf_path=Path("benchmark.xml"),
    output_path=Path("checklist.ckl"),
    asset_name="SERVER-01",
    asset_ip="192.168.1.100",
    apply_boilerplate=True
)

# Merge
merge_report = proc.merge(
    base_path=Path("current.ckl"),
    history_paths=[Path("old1.ckl"), Path("old2.ckl")],
    output_path=Path("merged.ckl")
)
```

**Testing Requirements**:
- Test XCCDF→CKL conversion (various benchmarks)
- Test merge logic (history preservation)
- Test diff functionality
- Test repair mode
- Test statistics generation
- Integration tests with real STIG files

**Thread Safety**: No

---

### 6.2 remediation/extractor.py

**Purpose**: Extract remediation commands from XCCDF.

**Source Lines**: 3335-3977

**Dependencies**:
- `stig_assessor.remediation.models`
- `stig_assessor.xml.*`
- `stig_assessor.io.*`
- `stig_assessor.core.*`

**Public API**:

```python
from pathlib import Path
from typing import List, Dict, Any
from xml.etree.ElementTree import ElementTree

class FixExt:
    """
    Fix extraction from XCCDF benchmarks.

    Thread-safe: No
    """

    def __init__(self, xccdf_path: Path):
        """
        Initialize extractor.

        Args:
            xccdf_path: XCCDF benchmark file
        """
        from stig_assessor.io.file_ops import FO

        self.xccdf_path = xccdf_path
        self.xccdf_tree = FO.load_xml(xccdf_path)
        self.fixes: List[Fix] = []

    def extract(self) -> int:
        """
        Extract all fixes from XCCDF.

        Returns:
            Number of fixes extracted
        """
        from stig_assessor.remediation.models import Fix
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        root = self.xccdf_tree.getroot()
        groups = root.findall(f".//{Sch.ns('Group')}")

        for group in groups:
            rule = group.find(Sch.ns('Rule'))
            if rule is None:
                continue

            # Extract VID
            vid = group.get('id', '')

            # Extract fix text
            fixtext_elem = rule.find(Sch.ns('fixtext'))
            if fixtext_elem is None:
                continue

            fixtext = XmlUtils.get_text(fixtext_elem)
            if not fixtext:
                continue

            # Extract commands
            commands = self._extract_commands(fixtext)

            # Extract metadata
            title = XmlUtils.get_text(rule.find(Sch.ns('title')))
            severity = rule.get('severity', 'medium')

            # Create Fix
            fix = Fix(
                vid=vid,
                title=title,
                severity=severity,
                fixtext=fixtext,
                commands=commands
            )
            self.fixes.append(fix)

        return len(self.fixes)

    def _extract_commands(self, fixtext: str) -> List[str]:
        """
        Extract executable commands from fixtext.

        Args:
            fixtext: Fix text from XCCDF

        Returns:
            List of commands
        """
        import re

        commands = []

        # Markdown code blocks
        code_block_pattern = re.compile(
            r'```(?:bash|powershell|sh)?\n(.*?)```',
            re.DOTALL | re.MULTILINE
        )
        for match in code_block_pattern.finditer(fixtext):
            commands.append(match.group(1).strip())

        # Inline code
        inline_pattern = re.compile(r'`([^`]+)`')
        for match in inline_pattern.finditer(fixtext):
            cmd = match.group(1).strip()
            if any(cmd.startswith(p) for p in ['sudo', 'chmod', 'chown', 'apt', 'yum']):
                commands.append(cmd)

        # Command lists
        bullet_pattern = re.compile(r'^\s*[-*]\s*(.+)$', re.MULTILINE)
        for match in bullet_pattern.finditer(fixtext):
            line = match.group(1).strip()
            if any(line.startswith(p) for p in ['sudo', 'Set-', 'New-', 'Update-']):
                commands.append(line)

        return commands

    def to_json(self, output_path: Path) -> None:
        """
        Export fixes to JSON.

        Args:
            output_path: Output JSON file
        """
        from stig_assessor.io.file_ops import FO
        import json

        data = [fix.to_dict() for fix in self.fixes]
        content = json.dumps(data, indent=2, ensure_ascii=False)
        FO.atomic_write(output_path, content)

    def to_csv(self, output_path: Path) -> None:
        """
        Export fixes to CSV.

        Args:
            output_path: Output CSV file
        """
        from stig_assessor.io.file_ops import FO
        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=['vid', 'title', 'severity', 'commands']
        )
        writer.writeheader()

        for fix in self.fixes:
            writer.writerow({
                'vid': fix.vid,
                'title': fix.title,
                'severity': fix.severity,
                'commands': '; '.join(fix.commands)
            })

        FO.atomic_write(output_path, output.getvalue())

    def to_bash(self, output_path: Path, dry_run: bool = False) -> None:
        """
        Generate Bash remediation script.

        Args:
            output_path: Output .sh file
            dry_run: Add --dry-run flags
        """
        lines = [
            "#!/usr/bin/env bash",
            "# STIG Remediation Script",
            f"# Generated from: {self.xccdf_path.name}",
            "",
            "set -euo pipefail",
            ""
        ]

        for fix in self.fixes:
            lines.append(f"# {fix.vid}: {fix.title}")
            for cmd in fix.commands:
                if 'powershell' not in cmd.lower():
                    if dry_run:
                        cmd = cmd + " --dry-run"
                    lines.append(cmd)
            lines.append("")

        from stig_assessor.io.file_ops import FO
        FO.atomic_write(output_path, "\n".join(lines))

    def to_powershell(self, output_path: Path, dry_run: bool = False) -> None:
        """
        Generate PowerShell remediation script.

        Args:
            output_path: Output .ps1 file
            dry_run: Add -WhatIf flags
        """
        lines = [
            "# STIG Remediation Script",
            f"# Generated from: {self.xccdf_path.name}",
            "",
            "$ErrorActionPreference = 'Stop'",
            ""
        ]

        for fix in self.fixes:
            lines.append(f"# {fix.vid}: {fix.title}")
            for cmd in fix.commands:
                if any(cmd.startswith(p) for p in ['Set-', 'New-', 'Update-']):
                    if dry_run:
                        cmd = cmd + " -WhatIf"
                    lines.append(cmd)
            lines.append("")

        from stig_assessor.io.file_ops import FO
        FO.atomic_write(output_path, "\n".join(lines))
```

**Testing Requirements**:
- Test command extraction (all patterns)
- Test multi-format export (JSON, CSV, Bash, PowerShell)
- Test dry-run script generation
- Test with various XCCDF formats

**Thread Safety**: No

---

(Continuing in next message due to length...)

Would you like me to continue with the remaining specifications (remediation processor, evidence manager, and UI modules), plus the interface contracts, migration strategy, and testing requirements sections?
### 6.3 remediation/processor.py

**Purpose**: Process remediation results and update checklists.

**Source Lines**: 4018-4291

**Dependencies**:
- `stig_assessor.remediation.models`
- `stig_assessor.processor.processor`
- `stig_assessor.xml.*`
- `stig_assessor.io.*`

**Public API**:

```python
from pathlib import Path
from typing import List, Dict, Any, Optional

class FixResPro:
    """
    Remediation results processor.

    Thread-safe: No
    """

    def __init__(self):
        """Initialize results processor."""
        from stig_assessor.core.logging import LOG

        self.log = LOG
        self.results: List[FixResult] = []

    def load(self, results_path: Path) -> int:
        """
        Load remediation results from JSON.

        Args:
            results_path: JSON file with results

        Returns:
            Number of results loaded

        Raises:
            FileError: If file invalid
        """
        from stig_assessor.io.file_ops import FO
        from stig_assessor.remediation.models import FixResult
        import json

        content = FO.read_with_fallback(results_path)
        data = json.loads(content)

        # Support both array and object payloads
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict) and 'results' in data:
            items = data['results']
        else:
            items = [data]

        # Parse results
        for item in items:
            result = FixResult.from_dict(item)
            self.results.append(result)

        # Deduplicate by VID (keep latest)
        seen = {}
        for result in self.results:
            if result.vid not in seen:
                seen[result.vid] = result

        self.results = list(seen.values())
        return len(self.results)

    def update_ckl(
        self,
        ckl_path: Path,
        output_path: Path,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Update CKL file with remediation results.

        Args:
            ckl_path: Input CKL file
            output_path: Output CKL file
            dry_run: Don't save changes

        Returns:
            Update report dict

        Raises:
            ValidationError: If CKL invalid
        """
        from stig_assessor.io.file_ops import FO
        from stig_assessor.validation.validator import Val
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils
        from stig_assessor.xml.sanitizer import San

        self.log.info(f"Updating CKL with remediation results", ckl=ckl_path)

        # Load CKL
        tree = FO.load_xml(ckl_path)
        Val.validate_ckl(tree, strict=True)

        # Update each VULN
        stats = {
            "total_results": len(self.results),
            "updated": 0,
            "not_found": 0,
            "errors": 0,
            "changes": []
        }

        root = tree.getroot()
        vulns = root.findall(f".//{Sch.VULN}")

        # Build VID → VULN map
        vuln_map = {}
        for vuln in vulns:
            vid = XmlUtils.get_vid(vuln)
            if vid:
                vuln_map[vid] = vuln

        # Apply results
        for result in self.results:
            if result.vid not in vuln_map:
                stats["not_found"] += 1
                self.log.warning(f"VID not found in CKL: {result.vid}")
                continue

            vuln = vuln_map[result.vid]

            try:
                # Update STATUS
                status_elem = vuln.find(Sch.STATUS)
                if status_elem is None:
                    import xml.etree.ElementTree as ET
                    status_elem = ET.SubElement(vuln, Sch.STATUS)

                old_status = status_elem.text or "Not_Reviewed"
                status_elem.text = San.normalize_status(result.status)

                # Update FINDING_DETAILS
                finding_elem = vuln.find(Sch.FINDING_DETAILS)
                if finding_elem is None:
                    import xml.etree.ElementTree as ET
                    finding_elem = ET.SubElement(vuln, Sch.FINDING_DETAILS)

                old_finding = finding_elem.text or ""

                # Append evidence if not replacing
                if result.finding_details:
                    if old_finding and not result.finding_details.startswith(old_finding):
                        new_finding = f"{old_finding}\n\n--- Remediation Evidence ---\n{result.finding_details}"
                    else:
                        new_finding = result.finding_details
                    finding_elem.text = San.txt(new_finding, max_len=65000)

                # Update COMMENTS
                if result.comments:
                    comments_elem = vuln.find(Sch.COMMENTS)
                    if comments_elem is None:
                        import xml.etree.ElementTree as ET
                        comments_elem = ET.SubElement(vuln, Sch.COMMENTS)

                    old_comments = comments_elem.text or ""
                    new_comments = f"{old_comments}\n{result.comments}" if old_comments else result.comments
                    comments_elem.text = San.txt(new_comments, max_len=32000)

                stats["updated"] += 1
                stats["changes"].append({
                    "vid": result.vid,
                    "old_status": old_status,
                    "new_status": result.status
                })

            except Exception as e:
                stats["errors"] += 1
                self.log.error(f"Failed to update {result.vid}: {e}")

        # Save
        if not dry_run:
            FO.save_xml(tree, output_path)
            self.log.info(f"Updated CKL saved", updated=stats["updated"])
        else:
            self.log.info(f"Dry run complete", would_update=stats["updated"])

        return stats

    def generate_report(self, format: str = "text") -> str:
        """
        Generate remediation report.

        Args:
            format: Output format (text, json, csv)

        Returns:
            Report content
        """
        if format == "json":
            import json
            return json.dumps([r.to_dict() for r in self.results], indent=2)

        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=['vid', 'status', 'success', 'timestamp']
            )
            writer.writeheader()
            for r in self.results:
                writer.writerow(r.to_dict())
            return output.getvalue()

        else:  # text
            lines = ["Remediation Results Report", "=" * 50, ""]
            for r in self.results:
                lines.append(f"{r.vid}: {r.status} ({'✓' if r.success else '✗'})")
            return "\n".join(lines)
```

**Testing Requirements**:
- Test JSON loading (array/object payloads)
- Test CKL update logic
- Test deduplication
- Test dry-run mode
- Test report generation (all formats)
- Test error handling

**Thread Safety**: No

---

### 6.4 evidence/manager.py

**Purpose**: Evidence file lifecycle management.

**Source Lines**: 4338-4598

**Dependencies**:
- `stig_assessor.evidence.models`
- `stig_assessor.core.*`
- `stig_assessor.io.*`

**Public API**:

```python
from pathlib import Path
from typing import List, Dict, Optional
import zipfile

class EvidenceMgr:
    """
    Evidence file lifecycle manager (Singleton).

    Thread-safe: No
    """

    _instance: Optional['EvidenceMgr'] = None

    def __new__(cls) -> 'EvidenceMgr':
        """Singleton implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize evidence manager."""
        if hasattr(self, '_initialized'):
            return

        from stig_assessor.core.config import CFG

        self.evidence_dir = CFG.evidence_dir
        self.metadata: Dict[str, List[EvidenceMeta]] = {}  # VID → [metadata]
        self._load_metadata()
        self._initialized = True

    def _load_metadata(self) -> None:
        """Load evidence metadata from disk."""
        from stig_assessor.evidence.models import EvidenceMeta
        import json

        metadata_file = self.evidence_dir / "metadata.json"
        if not metadata_file.exists():
            return

        try:
            from stig_assessor.io.file_ops import FO
            content = FO.read_with_fallback(metadata_file)
            data = json.loads(content)

            for vid, items in data.items():
                self.metadata[vid] = [EvidenceMeta.from_dict(item) for item in items]

        except Exception as e:
            from stig_assessor.core.logging import LOG
            LOG.error(f"Failed to load evidence metadata: {e}")

    def _save_metadata(self) -> None:
        """Save evidence metadata to disk."""
        import json
        from stig_assessor.io.file_ops import FO

        data = {
            vid: [meta.to_dict() for meta in metas]
            for vid, metas in self.metadata.items()
        }

        metadata_file = self.evidence_dir / "metadata.json"
        content = json.dumps(data, indent=2, ensure_ascii=False)
        FO.atomic_write(metadata_file, content, backup=False)

    def import_file(
        self,
        vid: str,
        source_path: Path,
        description: str = "",
        category: str = "general"
    ) -> EvidenceMeta:
        """
        Import evidence file.

        Args:
            vid: Vulnerability ID
            source_path: Source file path
            description: Evidence description
            category: Evidence category

        Returns:
            Evidence metadata

        Raises:
            FileError: If import fails
        """
        from stig_assessor.evidence.models import EvidenceMeta
        from stig_assessor.io.file_ops import FO
        from stig_assessor.exceptions import FileError
        import shutil
        import hashlib

        if not source_path.exists():
            raise FileError(f"Source file not found: {source_path}")

        # Create VID directory
        vid_dir = self.evidence_dir / vid
        vid_dir.mkdir(exist_ok=True)

        # Generate unique filename
        file_ext = source_path.suffix
        timestamp = int(time.time())
        dest_filename = f"{timestamp}_{source_path.name}"
        dest_path = vid_dir / dest_filename

        # Check for duplicates (by content hash)
        source_hash = self._compute_hash(source_path)
        for meta in self.metadata.get(vid, []):
            if meta.file_hash == source_hash:
                from stig_assessor.core.logging import LOG
                LOG.info(f"Duplicate evidence detected: {source_path.name}")
                return meta

        # Copy file
        try:
            shutil.copy2(source_path, dest_path)
        except Exception as e:
            raise FileError(f"Failed to copy evidence: {e}")

        # Create metadata
        meta = EvidenceMeta(
            vid=vid,
            filename=dest_filename,
            file_path=str(dest_path),
            file_size=dest_path.stat().st_size,
            file_hash=source_hash,
            description=description,
            category=category,
            imported_at=datetime.now(timezone.utc)
        )

        # Save metadata
        if vid not in self.metadata:
            self.metadata[vid] = []
        self.metadata[vid].append(meta)
        self._save_metadata()

        return meta

    def export_all(self, output_dir: Path) -> int:
        """
        Export all evidence to directory.

        Args:
            output_dir: Output directory

        Returns:
            Number of files exported
        """
        import shutil

        output_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        for vid, metas in self.metadata.items():
            vid_dir = output_dir / vid
            vid_dir.mkdir(exist_ok=True)

            for meta in metas:
                source = Path(meta.file_path)
                if source.exists():
                    dest = vid_dir / meta.filename
                    shutil.copy2(source, dest)
                    count += 1

        return count

    def package(self, output_zip: Path) -> Dict[str, Any]:
        """
        Package all evidence into ZIP file.

        Args:
            output_zip: Output ZIP file path

        Returns:
            Package statistics

        Raises:
            FileError: If packaging fails
        """
        from stig_assessor.exceptions import FileError
        import zipfile

        try:
            with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add metadata
                import json
                metadata_json = json.dumps(
                    {vid: [m.to_dict() for m in metas]
                     for vid, metas in self.metadata.items()},
                    indent=2
                )
                zf.writestr("metadata.json", metadata_json)

                # Add files
                file_count = 0
                total_size = 0

                for vid, metas in self.metadata.items():
                    for meta in metas:
                        source = Path(meta.file_path)
                        if source.exists():
                            arc_path = f"{vid}/{meta.filename}"
                            zf.write(source, arc_path)
                            file_count += 1
                            total_size += meta.file_size

            return {
                "success": True,
                "file_count": file_count,
                "total_size": total_size,
                "output_file": str(output_zip)
            }

        except Exception as e:
            raise FileError(f"Failed to package evidence: {e}")

    def delete(self, vid: str, filename: Optional[str] = None) -> int:
        """
        Delete evidence.

        Args:
            vid: Vulnerability ID
            filename: Specific file (None = delete all for VID)

        Returns:
            Number of files deleted
        """
        if vid not in self.metadata:
            return 0

        count = 0

        if filename is None:
            # Delete all for VID
            for meta in self.metadata[vid]:
                path = Path(meta.file_path)
                if path.exists():
                    path.unlink()
                    count += 1

            del self.metadata[vid]

        else:
            # Delete specific file
            new_metas = []
            for meta in self.metadata[vid]:
                if meta.filename == filename:
                    path = Path(meta.file_path)
                    if path.exists():
                        path.unlink()
                        count += 1
                else:
                    new_metas.append(meta)

            if new_metas:
                self.metadata[vid] = new_metas
            else:
                del self.metadata[vid]

        self._save_metadata()
        return count

    def list_by_vid(self, vid: str) -> List[EvidenceMeta]:
        """Get all evidence for VID."""
        return self.metadata.get(vid, [])

    def _compute_hash(self, path: Path) -> str:
        """Compute SHA256 hash of file."""
        import hashlib

        hasher = hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

# Module-level singleton
EVIDENCE = EvidenceMgr()
```

**Testing Requirements**:
- Test import (duplicates, large files)
- Test export/package
- Test delete operations
- Test metadata persistence
- Test hash computation

**Thread Safety**: No

---

## Level 7: User Interface

### 7.1 ui/cli.py

**Purpose**: CLI argument parsing and main entry point.

**Source Lines**: 5620+ (main function)

**Dependencies**: ALL modules

**Public API**:

```python
from typing import List, Optional
import argparse
import sys

def main(argv: Optional[List[str]] = None) -> int:
    """
    Main CLI entry point.

    Args:
        argv: Command-line arguments (None = sys.argv)

    Returns:
        Exit code (0 = success)
    """
    parser = argparse.ArgumentParser(
        description="STIG Assessor Complete - DoD STIG assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    # Verbosity
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    # Create command group
    create_group = parser.add_argument_group("Create CKL from XCCDF")
    create_group.add_argument("--create", action="store_true")
    create_group.add_argument("--xccdf", type=Path)
    create_group.add_argument("--out", type=Path)
    create_group.add_argument("--asset", type=str)
    create_group.add_argument("--ip", type=str, default="")
    create_group.add_argument("--mac", type=str, default="")
    create_group.add_argument("--role", type=str, default="None")
    create_group.add_argument("--marking", type=str, default="")
    create_group.add_argument("--apply-boilerplate", action="store_true")

    # Merge command group
    merge_group = parser.add_argument_group("Merge Checklists")
    merge_group.add_argument("--merge", action="store_true")
    merge_group.add_argument("--base", type=Path)
    merge_group.add_argument("--histories", type=Path, nargs="+")
    merge_group.add_argument("--merge-out", type=Path)

    # Fix extraction group
    fix_group = parser.add_argument_group("Extract Fixes")
    fix_group.add_argument("--extract", type=Path)
    fix_group.add_argument("--outdir", type=Path)
    fix_group.add_argument("--script-dry-run", action="store_true")

    # Remediation group
    rem_group = parser.add_argument_group("Apply Remediation Results")
    rem_group.add_argument("--apply-results", type=Path)
    rem_group.add_argument("--checklist", type=Path)
    rem_group.add_argument("--results-out", type=Path)

    # Evidence group
    ev_group = parser.add_argument_group("Evidence Management")
    ev_group.add_argument("--import-evidence", type=Path, nargs=2, metavar=("VID", "FILE"))
    ev_group.add_argument("--export-evidence", type=Path)
    ev_group.add_argument("--package-evidence", type=Path)

    # GUI
    parser.add_argument("--gui", action="store_true", help="Launch GUI")

    # Parse
    args = parser.parse_args(argv)

    # Setup logging
    from stig_assessor.core.logging import LOG
    LOG.set_verbose(args.verbose)

    # Dispatch commands
    try:
        if args.gui:
            return run_gui()

        elif args.create:
            return cmd_create(args)

        elif args.merge:
            return cmd_merge(args)

        elif args.extract:
            return cmd_extract(args)

        elif args.apply_results:
            return cmd_apply_results(args)

        elif args.import_evidence:
            return cmd_import_evidence(args)

        elif args.export_evidence:
            return cmd_export_evidence(args)

        elif args.package_evidence:
            return cmd_package_evidence(args)

        else:
            parser.print_help()
            return 0

    except Exception as e:
        from stig_assessor.core.logging import LOG
        LOG.error(f"Command failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

def cmd_create(args) -> int:
    """Execute create command."""
    from stig_assessor.processor.processor import Proc

    proc = Proc()
    report = proc.xccdf_to_ckl(
        xccdf_path=args.xccdf,
        output_path=args.out,
        asset_name=args.asset,
        asset_ip=args.ip,
        asset_mac=args.mac,
        role=args.role,
        marking=args.marking,
        apply_boilerplate=args.apply_boilerplate
    )

    print(f"✓ Created CKL: {report['output_file']}")
    print(f"  Rules processed: {report['rules_processed']}")
    return 0

def cmd_merge(args) -> int:
    """Execute merge command."""
    from stig_assessor.processor.processor import Proc

    proc = Proc()
    report = proc.merge(
        base_path=args.base,
        history_paths=args.histories,
        output_path=args.merge_out
    )

    print(f"✓ Merged checklist: {report['output_file']}")
    print(f"  VULNs merged: {report['vulns_merged']}")
    return 0

# ... other command implementations ...

def run_gui() -> int:
    """Launch GUI."""
    from stig_assessor.core.deps import Deps

    if not Deps.has_tkinter():
        print("Error: tkinter not available. Install python3-tk.")
        return 1

    from stig_assessor.ui.gui import GUI

    app = GUI()
    app.run()
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

**Testing Requirements**:
- Test all CLI commands
- Test argument parsing
- Test error handling
- Test help messages
- Integration tests

**Thread Safety**: N/A (entry point)

---

### 7.2 ui/gui.py

**Purpose**: Tkinter-based graphical interface.

**Source Lines**: 4647+ (GUI class if exists)

**Dependencies**:
- ALL modules
- tkinter (optional)

**Public API**:

```python
class GUI:
    """
    Graphical user interface (tkinter).

    Thread-safe: Partial (async operations use threads)
    """

    def __init__(self):
        """Initialize GUI."""
        import tkinter as tk
        from tkinter import ttk

        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("900x700")

        self._build_ui()

    def _build_ui(self) -> None:
        """Build UI components."""
        # Tabs for different operations
        # Forms for each command
        # Progress bars
        # Status messages
        pass

    def run(self) -> None:
        """Start GUI event loop."""
        self.root.mainloop()

    def _run_async(self, func: Callable, callback: Callable) -> None:
        """Run function in background thread."""
        import threading

        def worker():
            try:
                result = func()
                self.root.after(0, lambda: callback(result, None))
            except Exception as e:
                self.root.after(0, lambda: callback(None, e))

        threading.Thread(target=worker, daemon=True).start()
```

**Testing Requirements**:
- Manual GUI testing
- Test async operations
- Test all forms
- Test error dialogs

**Thread Safety**: Partial (UI thread + worker threads)

---

### 7.3 ui/presets.py

**Purpose**: GUI preset management.

**Source Lines**: 4599-4646

**Dependencies**:
- `stig_assessor.core.*`
- `stig_assessor.io.*`

**Public API**:

```python
class PresetMgr:
    """
    GUI preset manager (Singleton).

    Thread-safe: No
    """

    _instance: Optional['PresetMgr'] = None

    def __new__(cls) -> 'PresetMgr':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return

        from stig_assessor.core.config import CFG

        self.preset_dir = CFG.preset_dir
        self.presets: Dict[str, Dict[str, Any]] = {}
        self.load()
        self._initialized = True

    def load(self) -> None:
        """Load all presets from disk."""
        # Load JSON files from preset_dir
        pass

    def save(self, name: str, preset_data: Dict[str, Any]) -> None:
        """Save preset."""
        # Save to JSON file
        pass

    def delete(self, name: str) -> bool:
        """Delete preset."""
        # Remove JSON file
        pass

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """Get preset by name."""
        return self.presets.get(name)

    def list_all(self) -> List[str]:
        """List all preset names."""
        return list(self.presets.keys())
```

**Testing Requirements**:
- Test load/save/delete
- Test preset application
- Test JSON serialization

**Thread Safety**: No

---

## Interface Contracts

### Module Communication Patterns

**1. Error Propagation**

All modules propagate errors using custom exceptions:

```python
try:
    tree = FO.load_xml(path)
except FileError as e:
    LOG.error(f"Load failed: {e}")
    raise  # Re-raise for caller
```

**2. Logging Pattern**

All modules use centralized logging:

```python
from stig_assessor.core.logging import LOG

LOG.info("Operation started", param1=value1)
# ... operation ...
LOG.info("Operation complete", result_count=123)
```

**3. Configuration Access**

Modules access config via singleton:

```python
from stig_assessor.core.config import CFG

output_dir = CFG.export_dir
```

**4. XML Handling**

Standard pattern for XML operations:

```python
from stig_assessor.io.file_ops import FO
from stig_assessor.xml.utils import XmlUtils
from stig_assessor.xml.sanitizer import San

# Load
tree = FO.load_xml(path)

# Process
for elem in tree.findall(".//TAG"):
    text = XmlUtils.get_text(elem)
    safe_text = San.txt(text)

# Save
FO.save_xml(tree, output_path)
```

---

## Migration Strategy

### Phase 1: Foundation (Week 1)

**Day 1-2**: Create package structure
- Create all `__init__.py` files
- Define `stig_assessor/__init__.py` with version export:

```python
"""STIG Assessor Complete - Modular Package"""

from stig_assessor.core.constants import VERSION, BUILD_DATE, APP_NAME

__version__ = VERSION
__all__ = ["VERSION", "BUILD_DATE", "APP_NAME"]
```

**Day 3-4**: Extract Level 1 modules
- `exceptions.py` - copy exception classes
- `core/constants.py` - copy constants and enums
- Test imports

**Day 5**: Extract Level 2 core infrastructure
- `core/state.py`, `core/deps.py`, `core/logging.py`, `core/config.py`
- Update imports to use new modules
- Test initialization

### Phase 2: XML & I/O (Week 2)

**Day 1-2**: Extract XML modules
- `xml/schema.py`, `xml/sanitizer.py`, `xml/utils.py`
- Update all XML operations to use new modules

**Day 3-5**: Extract I/O module
- `io/file_ops.py`
- Critical: Test atomic writes thoroughly
- Verify backup logic

### Phase 3: Business Logic (Week 3)

**Day 1**: Validation
- `validation/validator.py`

**Day 2-3**: History
- `history/models.py`, `history/manager.py`
- Test bisect insertion

**Day 4**: Templates
- `templates/boilerplate.py`

**Day 5**: Integration testing

### Phase 4: Core Processor (Week 4)

**Day 1-4**: Main processor
- `processor/processor.py`
- Most complex module - careful extraction
- Test XCCDF→CKL conversion
- Test merge operations

**Day 5**: Integration testing

### Phase 5: Remediation & Evidence (Week 5)

**Day 1-2**: Remediation
- `remediation/models.py`, `remediation/extractor.py`, `remediation/processor.py`

**Day 3-4**: Evidence
- `evidence/models.py`, `evidence/manager.py`

**Day 5**: Integration testing

### Phase 6: UI & Final (Week 6)

**Day 1-2**: CLI
- `ui/cli.py`
- Update `__main__.py`

**Day 3**: GUI & Presets
- `ui/gui.py`, `ui/presets.py`

**Day 4**: Backward compatibility wrapper
- Update `STIG_Script.py` to import from package:

```python
#!/usr/bin/env python3
"""Backward compatibility wrapper for STIG_Script.py"""

from stig_assessor.ui.cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())
```

**Day 5**: Final testing & documentation

---

## Testing Requirements

### Unit Tests (Per Module)

**Structure**:
```
tests/
├── test_core/
│   ├── test_constants.py
│   ├── test_state.py
│   ├── test_config.py
│   ├── test_logging.py
│   └── test_deps.py
├── test_xml/
│   ├── test_schema.py
│   ├── test_sanitizer.py
│   └── test_utils.py
├── test_io/
│   └── test_file_ops.py
├── test_validation/
│   └── test_validator.py
├── test_history/
│   ├── test_models.py
│   └── test_manager.py
├── test_templates/
│   └── test_boilerplate.py
├── test_processor/
│   └── test_processor.py
├── test_remediation/
│   ├── test_models.py
│   ├── test_extractor.py
│   └── test_processor.py
├── test_evidence/
│   ├── test_models.py
│   └── test_manager.py
└── test_integration/
    ├── test_xccdf_to_ckl.py
    ├── test_merge.py
    ├── test_remediation_flow.py
    └── test_evidence_flow.py
```

**Coverage Target**: >80% line coverage

### Integration Tests

**Test Scenarios**:

1. **Full XCCDF→CKL Workflow**
   - Load real STIG benchmark
   - Convert to CKL
   - Validate with STIG Viewer schema
   - Apply boilerplate
   - Verify all VULNs present

2. **Merge Workflow**
   - Create 3 checklists with different statuses
   - Merge into single file
   - Verify history preservation
   - Verify deduplication

3. **Remediation Workflow**
   - Extract fixes from XCCDF
   - Generate remediation scripts
   - Create mock results JSON
   - Apply results to CKL
   - Verify status changes

4. **Evidence Workflow**
   - Import multiple evidence files
   - Export to directory
   - Package to ZIP
   - Verify integrity

### Performance Tests

**Benchmarks**:

- **Large file handling**: 15,000 VULN CKL (should process in <60s)
- **Merge performance**: 100 files (should complete in <5 min)
- **Memory usage**: Should not exceed 500MB for largest files

### Compatibility Tests

- **Python versions**: 3.9, 3.10, 3.11, 3.12
- **Platforms**: Windows 10/11, Ubuntu 20.04/22.04, RHEL 8/9
- **STIG Viewer**: Validate output with STIG Viewer 2.18

---

## Build & Distribution

### Single-File Distribution

Create build script to merge all modules:

```python
# build_single.py
"""Build single-file distribution from modular source."""

import ast
from pathlib import Path

def merge_modules() -> str:
    """Merge all modules into single file."""
    # Read all module files
    # Remove import statements
    # Concatenate in dependency order
    # Return merged content
    pass

if __name__ == "__main__":
    merged = merge_modules()
    Path("dist/STIG_Script.py").write_text(merged)
```

### Package Distribution

**setup.py**:

```python
from setuptools import setup, find_packages

setup(
    name="stig-assessor",
    version="8.0.0",
    description="DoD STIG assessment tool",
    author="Your Organization",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "stig-assessor=stig_assessor.ui.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
```

---

## Documentation Updates

### Files to Update

1. **CLAUDE.md**
   - Update architecture section with new structure
   - Update line numbers (will change significantly)
   - Add module index
   - Update Quick Reference

2. **README.md** (create if missing)
   - Installation instructions
   - Usage examples
   - Module overview
   - Development guide

3. **API.md** (new)
   - Complete API reference
   - All public classes/functions
   - Usage examples

4. **MIGRATION.md** (new)
   - Guide for users migrating from 7.x to 8.0
   - Breaking changes (if any)
   - Import path updates

---

## Rollout Checklist

### Pre-Release

- [ ] All modules extracted and tested
- [ ] Unit tests >80% coverage
- [ ] Integration tests passing
- [ ] Performance benchmarks met
- [ ] Documentation updated
- [ ] CLAUDE.md updated
- [ ] Single-file build tested
- [ ] Package install tested

### Release

- [ ] Version bumped to 8.0.0
- [ ] BUILD_DATE updated
- [ ] Git tag created
- [ ] Release notes written
- [ ] Backward compatibility wrapper tested

### Post-Release

- [ ] Monitor for issues
- [ ] Update wiki/docs site
- [ ] Announce to users
- [ ] Collect feedback

---

## Success Criteria

✓ **Parallel Development Enabled**: 5+ teams can work simultaneously
✓ **Testability Improved**: Unit tests cover all modules
✓ **Cognitive Load Reduced**: No file >500 lines
✓ **Backward Compatible**: Old scripts work without changes
✓ **Performance Maintained**: No regression in benchmarks
✓ **Air-Gap Certified**: Zero external dependencies
✓ **STIG Viewer Compliant**: All outputs validate

---

**END OF SPECIFICATION**

**Questions for Development Teams?**

Contact: [Maintainer information]
