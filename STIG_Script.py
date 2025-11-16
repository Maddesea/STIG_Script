#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STIG Assessor - Complete Production Edition v7.0.0
───────────────────────────────────────────────────────────────────────────────
PRODUCTION-READY • ZERO-DEPENDENCY • AIR-GAP CERTIFIED • BULLETPROOF

Highlights
    ✓ XCCDF ➜ CKL conversion (STIG Viewer 2.18 schema compliant)
    ✓ Checklist merge (history preserving, newest → oldest)
    ✓ Fix extraction (JSON / CSV / Bash / PowerShell, multi-line aware)
    ✓ Bulk remediation ingest (single JSON run captures 300+ checks at once)
    ✓ Evidence lifecycle (import / export / package)
    ✓ History tracking (microsecond precision, deduplicated)
    ✓ Boilerplate templates (status-aware, customisable)
    ✓ Validation (comprehensive STIG Viewer compatibility)
    ✓ GUI with async operations (requires tkinter, optional)
    ✓ CLI feature parity with GUI

Release 7.0 Improvements
    ✓ Fix-text extraction rebuilt: better namespace handling, multi-block
      fixtext stitching, robust command scraping (Markdown blocks, inline,
      bullet lists, PowerShell transcripts, etc.)
    ✓ Remediation import rewritten to accept a single results JSON capturing
      hundreds of checks (array or object payloads). Deduplicates by Vuln ID,
      supports dry-run reporting, summarises deltas, and back-fills finding
      text while respecting existing content.
    ✓ XML sanitiser hardened (no silent truncation when non-string payloads
      encountered). Every write path atomic with rollback.
    ✓ Validation, merge, evidence, GUI and CLI refreshed with meaningful UX
      improvements (status bars, clearer logging, better error traces).
"""

from __future__ import annotations

import argparse
import atexit
import csv
import gc
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import queue
import re
import shutil
import signal
import sys
import tempfile
import threading
import time
import uuid
import warnings
import zipfile
from collections import OrderedDict, defaultdict
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, IO, Iterable, List, Optional, Tuple, Union

# Filter only specific warnings that are expected in air-gapped environments
warnings.filterwarnings("ignore", category=DeprecationWarning, module="xml")
warnings.filterwarnings("ignore", category=ResourceWarning)

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "7.0.0"
BUILD_DATE = "2025-10-28"
APP_NAME = "STIG Assessor Complete"
STIG_VIEWER_VERSION = "2.18"

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024
CHUNK_SIZE = 8192
MAX_RETRIES = 3
RETRY_DELAY = 0.5
MAX_XML_SIZE = 500 * 1024 * 1024

ENCODINGS = [
    "utf-8",
    "utf-8-sig",
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "latin-1",
    "cp1252",
    "iso-8859-1",
    "ascii",
]

# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ──────────────────────────────────────────────────────────────────────────────


class GlobalState:
    """Process wide shutdown coordination."""

    _instance: Optional["GlobalState"] = None
    _lock = threading.RLock()

    def __new__(cls) -> "GlobalState":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        self.shutdown = threading.Event()
        self.temps: List[Path] = []
        self.cleanups: List[callable] = []
        atexit.register(self.cleanup)
        self._setup_signals()

    def _setup_signals(self) -> None:
        def handler(sig, frame):
            print(f"\n[SIGNAL {sig}] Shutting down gracefully...", file=sys.stderr)
            self.shutdown.set()
            self.cleanup()
            sys.exit(0)

        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(Exception):
                signal.signal(sig, handler)

    def add_temp(self, path: Path) -> None:
        with self._lock:
            self.temps.append(path)

    def add_cleanup(self, func: callable) -> None:
        with self._lock:
            self.cleanups.append(func)

    def cleanup(self) -> None:
        with self._lock:
            if self.shutdown.is_set():
                return
            self.shutdown.set()

            for func in reversed(self.cleanups):
                with suppress(Exception):
                    func()

            for temp in self.temps:
                with suppress(Exception):
                    if temp and temp.exists():
                        temp.unlink()

            self.temps.clear()
            self.cleanups.clear()
            gc.collect()


GLOBAL = GlobalState()

# ──────────────────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ──────────────────────────────────────────────────────────────────────────────


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


# ──────────────────────────────────────────────────────────────────────────────
# DECORATORS
# ──────────────────────────────────────────────────────────────────────────────


def retry(
    attempts: int = MAX_RETRIES,
    delay: float = RETRY_DELAY,
    exceptions: Tuple[type, ...] = (IOError, OSError),
):
    """Retry decorator with exponential backoff."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            wait = delay
            last_err: Optional[BaseException] = None
            for attempt in range(1, attempts + 1):
                if GLOBAL.shutdown.is_set():
                    raise InterruptedError("Shutdown requested")
                try:
                    return func(*args, **kwargs)
                except exceptions as err:
                    last_err = err
                    if attempt < attempts:
                        time.sleep(wait)
                        wait *= 2
                    continue
            if last_err:
                raise last_err
            raise RuntimeError("Retry failed without captured exception")

        return wrapper

    return decorator


# ──────────────────────────────────────────────────────────────────────────────
# OPTIONAL DEPENDENCIES
# ──────────────────────────────────────────────────────────────────────────────


class Deps:
    """Optional dependency detection."""

    HAS_DEFUSEDXML = False
    HAS_TKINTER = False
    HAS_FCNTL = False
    HAS_MSVCRT = False

    @classmethod
    def check(cls) -> None:
        with suppress(Exception):
            from defusedxml import ElementTree as DET
            from io import StringIO

            DET.parse(StringIO("<test/>"))
            cls.HAS_DEFUSEDXML = True

        with suppress(Exception):
            import tkinter

            r = tkinter.Tk()
            r.withdraw()
            r.destroy()
            del r
            gc.collect()
            cls.HAS_TKINTER = True

        with suppress(Exception):
            import fcntl  # noqa: F401

            cls.HAS_FCNTL = True

        with suppress(Exception):
            import msvcrt  # noqa: F401

            cls.HAS_MSVCRT = True

    @classmethod
    def get_xml(cls):
        if cls.HAS_DEFUSEDXML:
            from defusedxml import ElementTree as ET
            from defusedxml.ElementTree import ParseError as XMLParseError
        else:
            import xml.etree.ElementTree as ET  # noqa: N813
            from xml.etree.ElementTree import ParseError as XMLParseError

        return ET, XMLParseError


Deps.check()
ET, XMLParseError = Deps.get_xml()

# Warn if defusedxml is not available (security risk)
if not Deps.HAS_DEFUSEDXML:
    print("WARNING: defusedxml not available. Falling back to unsafe XML parser.", file=sys.stderr)
    print("  Install defusedxml for protection against XML entity expansion attacks.", file=sys.stderr)

if Deps.HAS_TKINTER:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from tkinter.scrolledtext import ScrolledText

if Deps.HAS_FCNTL:
    import fcntl  # noqa: E402,F401

if Deps.HAS_MSVCRT:
    import msvcrt  # noqa: E402,F401

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────


class Cfg:
    """Application configuration."""

    IS_WIN = platform.system() == "Windows"
    IS_LIN = platform.system() == "Linux"
    IS_MAC = platform.system() == "Darwin"
    PY_VER = sys.version_info
    MIN_PY = (3, 9)
    PLATFORM = platform.system()

    HOME: Optional[Path] = None
    APP_DIR: Optional[Path] = None
    LOG_DIR: Optional[Path] = None
    BACKUP_DIR: Optional[Path] = None
    EVIDENCE_DIR: Optional[Path] = None
    TEMPLATE_DIR: Optional[Path] = None
    PRESET_DIR: Optional[Path] = None
    FIX_DIR: Optional[Path] = None
    EXPORT_DIR: Optional[Path] = None
    BOILERPLATE_FILE: Optional[Path] = None

    MAX_FILE = 500 * 1024 * 1024
    MAX_HIST = 200
    MAX_FIND = 65000
    MAX_COMM = 32000
    MAX_MERGE = 100
    MAX_VULNS = 15000
    KEEP_BACKUPS = 30
    KEEP_LOGS = 15

    _lock = threading.RLock()
    _done = False

    @classmethod
    def init(cls) -> None:
        with cls._lock:
            if cls._done:
                return

            candidates: List[Path] = []

            with suppress(Exception):
                candidates.append(Path.home())

            for env_var in ("USERPROFILE", "HOME"):
                val = os.environ.get(env_var)
                if val and os.path.exists(val):
                    candidates.append(Path(val))

            candidates.append(Path(tempfile.gettempdir()) / "stig_user")
            with suppress(Exception):
                candidates.append(Path.cwd() / ".stig_home")

            for candidate in candidates:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    tmp = candidate / f".stig_test_{os.getpid()}"
                    tmp.write_text("ok", encoding="utf-8")
                    tmp.unlink()
                    cls.HOME = candidate
                    break
                except Exception:
                    continue

            if not cls.HOME:
                raise RuntimeError("Cannot find writable home directory")

            cls.APP_DIR = cls.HOME / ".stig_assessor"
            cls.LOG_DIR = cls.APP_DIR / "logs"
            cls.BACKUP_DIR = cls.APP_DIR / "backups"
            cls.EVIDENCE_DIR = cls.APP_DIR / "evidence"
            cls.TEMPLATE_DIR = cls.APP_DIR / "templates"
            cls.PRESET_DIR = cls.APP_DIR / "presets"
            cls.FIX_DIR = cls.APP_DIR / "fixes"
            cls.EXPORT_DIR = cls.APP_DIR / "exports"
            cls.BOILERPLATE_FILE = cls.TEMPLATE_DIR / "boilerplate.json"

            required = [cls.APP_DIR, cls.LOG_DIR, cls.BACKUP_DIR]
            optional = [
                cls.EVIDENCE_DIR,
                cls.TEMPLATE_DIR,
                cls.PRESET_DIR,
                cls.FIX_DIR,
                cls.EXPORT_DIR,
            ]

            for directory in required:
                directory.mkdir(parents=True, exist_ok=True)
                tmp = directory / f".write_test_{os.getpid()}"
                tmp.write_text("ok", encoding="utf-8")
                tmp.unlink()

            for directory in optional:
                directory.mkdir(parents=True, exist_ok=True)

            cls._done = True

    @classmethod
    def check(cls) -> Tuple[bool, List[str]]:
        errs: List[str] = []

        if cls.PY_VER < cls.MIN_PY:
            errs.append(f"Python {cls.MIN_PY[0]}.{cls.MIN_PY[1]}+ required")

        for module in ("json", "hashlib", "pathlib", "logging", "zipfile", "csv", "uuid"):
            try:
                __import__(module)
            except Exception:
                errs.append(f"Missing stdlib module: {module}")

        try:
            ET.Element("test")
        except Exception:
            errs.append("XML parser failed")

        if cls.APP_DIR and not os.access(cls.APP_DIR, os.W_OK):
            errs.append(f"No write permission: {cls.APP_DIR}")

        return len(errs) == 0, errs

    @classmethod
    def cleanup_old(cls) -> Tuple[int, int]:
        def clean(directory: Path, keep: int, pattern: str) -> int:
            if not directory or not directory.exists():
                return 0
            removed = 0
            files = sorted(
                directory.glob(pattern),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in files[keep:]:
                with suppress(Exception):
                    old.unlink()
                    removed += 1
            return removed

        backups = clean(cls.BACKUP_DIR, cls.KEEP_BACKUPS, "*.bak")
        logs = clean(cls.LOG_DIR, cls.KEEP_LOGS, "*.log")
        return backups, logs


try:
    Cfg.init()
except Exception as exc:
    print(f"FATAL: Config initialisation failed: {exc}", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────


class Log:
    """Thread-safe logger with contextual metadata."""

    _instances: Dict[str, "Log"] = {}
    _lock = threading.RLock()

    def __new__(cls, name: str) -> "Log":
        with cls._lock:
            if name not in cls._instances:
                inst = super().__new__(cls)
                inst._initialised = False
                cls._instances[name] = inst
            return cls._instances[name]

    def __init__(self, name: str):
        if getattr(self, "_initialised", False):
            return

        with self._lock:
            if getattr(self, "_initialised", False):
                return
            self._initialised = True
            self.name = name
            self.log = logging.getLogger(name)
            self.log.setLevel(logging.INFO)
            self.log.handlers.clear()
            self.log.propagate = False
            self._ctx = threading.local()
            self._setup()

    def _setup(self) -> None:
        with suppress(Exception):
            console = logging.StreamHandler(sys.stderr)
            console.setLevel(logging.WARNING)
            console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.log.addHandler(console)

        with suppress(Exception):
            file_handler = logging.handlers.RotatingFileHandler(
                str(Cfg.LOG_DIR / f"{self.name}.log"),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)-8s] %(message)s",
                    "%Y-%m-%d %H:%M:%S",
                )
            )
            self.log.addHandler(file_handler)

    def ctx(self, **kw) -> None:
        if not hasattr(self._ctx, "data"):
            self._ctx.data = {}
        self._ctx.data.update(kw)

    def clear(self) -> None:
        if hasattr(self._ctx, "data"):
            self._ctx.data.clear()

    def _context_str(self) -> str:
        try:
            data = getattr(self._ctx, "data", {})
            if data:
                return "[" + ", ".join(f"{k}={v}" for k, v in data.items()) + "] "
        except Exception:
            # Silently ignore context extraction failures in logging helper
            pass
        return ""

    def _log(self, level: str, message: str, exc: bool = False) -> None:
        try:
            getattr(self.log, level)(self._context_str() + str(message), exc_info=exc)
        except Exception:
            # Fallback to stderr if logging system fails
            print(f"[{level.upper()}] {message}", file=sys.stderr)

    def d(self, msg: str) -> None:
        self._log("debug", msg)

    def i(self, msg: str) -> None:
        self._log("info", msg)

    def w(self, msg: str) -> None:
        self._log("warning", msg)

    def e(self, msg: str, exc: bool = False) -> None:
        self._log("error", msg, exc)

    def c(self, msg: str, exc: bool = False) -> None:
        self._log("critical", msg, exc)


LOG = Log("stig")

# ──────────────────────────────────────────────────────────────────────────────
# SCHEMA
# ──────────────────────────────────────────────────────────────────────────────


class Sch:
    ROOT = "CHECKLIST"
    COMMENT = f"DISA STIG Viewer :: {STIG_VIEWER_VERSION}"

    ASSET = (
        "ROLE",
        "ASSET_TYPE",
        "MARKING",
        "HOST_NAME",
        "HOST_IP",
        "HOST_MAC",
        "HOST_FQDN",
        "TARGET_COMMENT",
        "TECH_AREA",
        "TARGET_KEY",
        "WEB_OR_DATABASE",
        "WEB_DB_SITE",
        "WEB_DB_INSTANCE",
    )

    STIG = (
        "version",
        "classification",
        "customname",
        "stigid",
        "description",
        "filename",
        "releaseinfo",
        "title",
        "uuid",
        "notice",
        "source",
    )

    VULN = (
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
        "Check_Content_Ref",
        "Weight",
        "Class",
        "STIGRef",
        "TargetKey",
        "STIG_UUID",
    )

    STATUS = (
        "STATUS",
        "FINDING_DETAILS",
        "COMMENTS",
        "SEVERITY_OVERRIDE",
        "SEVERITY_JUSTIFICATION",
    )

    STAT_VALS = frozenset(["NotAFinding", "Open", "Not_Reviewed", "Not_Applicable"])
    SEV_VALS = frozenset(["high", "medium", "low"])
    MARKS = frozenset(["CUI", "UNCLASSIFIED", "SECRET", "TOP SECRET", "TS", "S", "U"])

    DEFS = {
        "Check_Content_Ref": "M",
        "Weight": "10.0",
        "Class": "Unclass",
        "Documentable": "false",
        "MARKING": "CUI",
        "ROLE": "None",
        "ASSET_TYPE": "Computing",
        "WEB_OR_DATABASE": "false",
        "IA_Controls": "",
        "False_Positives": "",
        "False_Negatives": "",
        "Mitigations": "",
        "Potential_Impact": "",
        "Third_Party_Tools": "",
        "Mitigation_Control": "",
        "Responsibility": "",
        "Security_Override_Guidance": "",
        "TECH_AREA": "",
        "TARGET_COMMENT": "",
        "WEB_DB_SITE": "",
        "WEB_DB_INSTANCE": "",
        "customname": "",
        "notice": "terms-of-use",
        "source": "STIG.DOD.MIL",
        "classification": "UNCLASSIFIED",
    }


# ──────────────────────────────────────────────────────────────────────────────
# SANITISER
# ──────────────────────────────────────────────────────────────────────────────


class San:
    """Input validation helpers."""

    ASSET = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")
    IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
    VULN = re.compile(r"^V-\d{1,10}$")
    UUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)

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
        if not value or (isinstance(value, str) and not value.strip()):
            raise ValidationError("Empty path")

        try:
            as_str = str(value).strip()
            if "\x00" in as_str:
                raise ValidationError("Null byte in path")

            if San.TRAV.search(as_str):
                LOG.w(f"Potential traversal sequence in path: {as_str}")

            path = Path(as_str)
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
        if not value or not str(value).strip():
            raise ValidationError("Empty asset")
        value = str(value).strip()[:255]
        if not San.ASSET.match(value):
            raise ValidationError(f"Invalid asset: {value}")
        return value

    @staticmethod
    def ip(value: str) -> str:
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
        if not value or not str(value).strip():
            raise ValidationError("Empty vulnerability ID")
        value = str(value).strip()
        if not San.VULN.match(value):
            raise ValidationError(f"Invalid vulnerability ID: {value}")
        return value

    @staticmethod
    def status(value: str) -> str:
        if not value:
            return "Not_Reviewed"
        value = str(value).strip()
        if value not in Sch.STAT_VALS:
            raise ValidationError(f"Invalid status: {value}")
        return value

    @staticmethod
    def sev(value: str) -> str:
        if not value:
            return "medium"
        value = str(value).strip().lower()
        if value not in Sch.SEV_VALS:
            LOG.w(f"Invalid severity '{value}', defaulting to 'medium'")
            return "medium"
        return value

    @staticmethod
    def xml(value: Any, mx: Optional[int] = None) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception as exc:
                # Cannot convert to string, return empty
                LOG.w(f"Failed to convert value to string for XML sanitization: {type(value)} - {exc}")
                return ""
        value = San.CTRL.sub("", value)
        value = (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )
        if mx is not None and len(value) > mx:
            value = value[: mx - 15] + "\n[TRUNCATED]"
        return value


# ──────────────────────────────────────────────────────────────────────────────
# FILE OPERATIONS
# ──────────────────────────────────────────────────────────────────────────────


class FO:
    """Safe file operations."""

    @staticmethod
    @contextmanager
    @retry()
    def atomic(target: Union[str, Path], mode: str = "w", enc: str = "utf-8", bak: bool = True) -> Generator[IO, None, None]:
        target = San.path(target, mkpar=True)
        tmp_path: Optional[Path] = None
        backup_path: Optional[Path] = None
        fh = None

        try:
            if bak and target.exists() and target.is_file():
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
                backup_path = Cfg.BACKUP_DIR / f"{target.stem}_{timestamp}{target.suffix}.bak"
                shutil.copy2(str(target), str(backup_path))

            fd, tmp_name = tempfile.mkstemp(
                dir=str(target.parent),
                prefix=f".stig_tmp_{os.getpid()}_",
                suffix=".tmp",
                text="b" not in mode,
            )
            os.close(fd)
            tmp_path = Path(tmp_name)
            GLOBAL.add_temp(tmp_path)

            if "b" in mode:
                fh = open(tmp_path, mode)
            else:
                fh = open(tmp_path, mode, encoding=enc, errors="replace", newline="\n")

            yield fh

            fh.flush()
            if not Cfg.IS_WIN:
                os.fsync(fh.fileno())
            else:
                with suppress(Exception):
                    fh.flush()
                    os.fsync(fh.fileno())
            fh.close()
            fh = None

            if Cfg.IS_WIN and target.exists():
                with suppress(PermissionError):
                    target.unlink()
                time.sleep(0.05)

            tmp_path.replace(target)
            tmp_path = None

            if bak:
                FO._clean_baks(target.stem)

        except Exception as exc:
            if fh:
                with suppress(Exception):
                    fh.close()
            if tmp_path and tmp_path.exists():
                with suppress(Exception):
                    tmp_path.unlink()
            if backup_path and backup_path.exists():
                with suppress(Exception):
                    if target.exists():
                        target.unlink()
                    shutil.copy2(str(backup_path), str(target))
            raise FileError(f"Atomic write failed: {exc}")
        finally:
            if tmp_path and tmp_path.exists():
                with suppress(Exception):
                    tmp_path.unlink()

    @staticmethod
    def _clean_baks(stem: str) -> None:
        with suppress(Exception):
            backups = sorted(
                Cfg.BACKUP_DIR.glob(f"{stem}_*.bak"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in backups[Cfg.KEEP_BACKUPS :]:
                with suppress(Exception):
                    old.unlink()

    @staticmethod
    def read(path: Union[str, Path]) -> str:
        path = San.path(path, exist=True, file=True)
        for encoding in ENCODINGS:
            try:
                # Use strict error handling to properly detect encoding issues
                with open(path, "r", encoding=encoding, errors="strict") as handle:
                    data = handle.read()
                # Remove BOM if present
                if data.startswith("\ufeff"):
                    data = data[1:]
                return data
            except (UnicodeDecodeError, UnicodeError):
                continue
        raise FileError(f"Unable to decode file with any known encoding: {path}")

    @staticmethod
    def parse_xml(path: Union[str, Path]):
        path = San.path(path, exist=True, file=True)
        try:
            return ET.parse(str(path))
        except XMLParseError as err:
            LOG.e(f"XML parse error: {err}")
            try:
                content = FO.read(path)
                content = re.sub(r"&(?!(amp|lt|gt|quot|apos);)", "&amp;", content)
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", suffix=".xml", delete=False
                ) as tmp:
                    tmp.write(content)
                    tmp_name = tmp.name
                try:
                    tree = ET.parse(tmp_name)
                    LOG.i("XML parsed successfully after entity sanitisation")
                    return tree
                finally:
                    with suppress(Exception):
                        os.unlink(tmp_name)
            except Exception as inner:
                raise ParseError(f"XML parse failed: {inner}")

    @staticmethod
    @retry(attempts=2)
    def zip(out_path: Union[str, Path], files: Dict[str, Union[str, Path]], base: Optional[str] = None) -> Path:
        out_path = San.path(out_path, mkpar=True)
        tmp_zip: Optional[Path] = None
        added = 0

        try:
            fd, tmp_name = tempfile.mkstemp(suffix=".zip", dir=out_path.parent)
            os.close(fd)
            tmp_zip = Path(tmp_name)

            with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                for arcname, source in files.items():
                    try:
                        source_path = San.path(source, exist=True, file=True)
                        final_arcname = f"{base}/{arcname}" if base else arcname
                        archive.write(str(source_path), arcname=final_arcname)
                        added += 1
                    except Exception as exc:
                        LOG.w(f"Skipping {arcname}: {exc}")

            if added == 0:
                raise FileError("No files added to zip")

            if Cfg.IS_WIN and out_path.exists():
                out_path.unlink()

            tmp_zip.replace(out_path)
            tmp_zip = None

            LOG.i(f"Created ZIP archive with {added} files")
            return out_path
        finally:
            if tmp_zip and tmp_zip.exists():
                with suppress(Exception):
                    tmp_zip.unlink()


# ──────────────────────────────────────────────────────────────────────────────
# HISTORY
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Hist:
    """History entry."""

    ts: datetime
    stat: str
    find: str
    comm: str
    src: str
    chk: str
    sev: str = "medium"
    who: str = ""

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            self.ts = self.ts.replace(tzinfo=timezone.utc)
        with suppress(Exception):
            self.stat = San.status(self.stat)
        with suppress(Exception):
            self.sev = San.sev(self.sev)
        if not self.who:
            self.who = os.getenv("USER") or os.getenv("USERNAME") or "System"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts.isoformat(),
            "stat": self.stat,
            "find": self.find,
            "comm": self.comm,
            "src": self.src,
            "chk": self.chk,
            "sev": self.sev,
            "who": self.who,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Hist":
        if not isinstance(data, dict):
            raise ValidationError("History payload must be object")

        ts = datetime.now(timezone.utc)
        ts_str = data.get("ts")
        if ts_str:
            with suppress(Exception):
                ts = datetime.fromisoformat(ts_str.rstrip("Z"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return cls(
            ts=ts,
            stat=data.get("stat", "Not_Reviewed"),
            find=str(data.get("find", "")),
            comm=str(data.get("comm", "")),
            src=str(data.get("src", "unknown")),
            chk=str(data.get("chk", "")) or "legacy",
            sev=str(data.get("sev", "medium")),
            who=str(data.get("who", "")),
        )


class HistMgr:
    """In-memory history manager."""

    def __init__(self):
        self._h: Dict[str, List[Hist]] = defaultdict(list)
        self._lock = threading.RLock()

    def add(
        self,
        vid: str,
        stat: str,
        find: str,
        comm: str,
        src: str,
        sev: str = "medium",
        who: str = "",
    ) -> bool:
        with self._lock:
            try:
                vid = San.vuln(vid)
                stat = San.status(stat)
                sev = San.sev(sev)
            except (ValidationError, ValueError) as exc:
                LOG.w(f"Failed to add history for {vid}: validation error: {exc}")
                return False

            if not find and not comm:
                return False

            summary = f"{stat}|{find}|{comm}|{sev}|{who}"
            try:
                digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:16]
            except (UnicodeEncodeError, AttributeError) as exc:
                LOG.w(f"Failed to compute digest for {vid}, using fallback: {exc}")
                digest = f"chk_{uuid.uuid4().hex[:6]}"

            if any(entry.chk == digest for entry in self._h[vid][-20:]):
                return False

            if not who:
                who = os.getenv("USER") or os.getenv("USERNAME") or "System"

            entry = Hist(
                ts=datetime.now(timezone.utc),
                stat=stat,
                find=find or "",
                comm=comm or "",
                src=src,
                chk=digest,
                sev=sev,
                who=who,
            )
            self._h[vid].append(entry)
            self._h[vid].sort(key=lambda e: e.ts)
            if len(self._h[vid]) > Cfg.MAX_HIST:
                self._compress(vid)
            return True

    def _compress(self, vid: str) -> None:
        entries = self._h[vid]
        if len(entries) <= Cfg.MAX_HIST:
            return

        head = entries[:15]
        tail = entries[-100:]
        middle = entries[15:-100]

        if middle:
            compressed = Hist(
                ts=middle[0].ts,
                stat="compressed",
                find=f"[{len(middle)} historical entries compressed]",
                comm="",
                src="system",
                chk="compressed",
                sev="info",
                who="system",
            )
            self._h[vid] = head + [compressed] + tail
        else:
            self._h[vid] = head + tail

    def merge_find(self, vid: str, current: str = "") -> str:
        with self._lock:
            history = self._h.get(vid)
            if not history:
                return current

            parts: List[str] = []
            if current.strip():
                parts.extend(
                    [
                        "┌" + "─" * 78 + "┐",
                        "│ CURRENT ASSESSMENT".center(80) + "│",
                        "└" + "─" * 78 + "┘",
                        "",
                        current.strip(),
                        "",
                    ]
                )

            parts.extend(
                [
                    "┌" + "─" * 78 + "┐",
                    "│ HISTORY (Most Recent → Oldest)".center(80) + "│",
                    "└" + "─" * 78 + "┘",
                    "",
                ]
            )

            for idx, entry in enumerate(reversed(history), 1):
                ts = entry.ts.strftime("%Y-%m-%d %H:%M:%S UTC")
                parts.extend(
                    [
                        f"╓─ Entry #{idx} {'★ CURRENT ★' if idx == 1 else ''}",
                        f"║ Time: {ts}",
                        f"║ Source: {entry.src}",
                        f"║ Status: {entry.stat} | Severity: {entry.sev}",
                        f"║ Assessor: {entry.who}",
                        "╟" + "─" * 79,
                        entry.find.strip() or "[No details]",
                        "╙" + "─" * 79,
                        "",
                    ]
                )

            result = "\n".join(parts)
            if len(result) > Cfg.MAX_FIND:
                result = result[: Cfg.MAX_FIND - 15] + "\n[TRUNCATED]"
            return result

    def merge_comm(self, vid: str, current: str = "") -> str:
        with self._lock:
            history = self._h.get(vid)
            if not history:
                return current

            parts: List[str] = []
            if current.strip():
                parts.extend(["═" * 80, "[CURRENT COMMENT]", current.strip(), "", ""])

            parts.extend(["═" * 80, "[COMMENT HISTORY]", "═" * 80, ""])

            count = 0
            for entry in reversed(history):
                if not entry.comm.strip():
                    continue
                count += 1
                ts = entry.ts.strftime("%Y-%m-%d %H:%M:%S UTC")
                parts.append(f"[{count}] {ts} | {entry.src} | {entry.stat}")
                parts.append(entry.comm.strip())
                parts.append("─" * 80)

            result = "\n".join(parts)
            if len(result) > Cfg.MAX_COMM:
                result = result[: Cfg.MAX_COMM - 15] + "\n[TRUNCATED]"
            return result

    def export(self, path: Union[str, Path]) -> None:
        path = San.path(path, mkpar=True)
        with self._lock:
            payload = {
                "meta": {
                    "generated": datetime.now(timezone.utc).isoformat(),
                    "version": VERSION,
                    "nvulns": len(self._h),
                    "nentries": sum(len(vals) for vals in self._h.values()),
                },
                "history": {
                    vid: [entry.as_dict() for entry in entries]
                    for vid, entries in self._h.items()
                },
            }

        with FO.atomic(path) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

        LOG.i(f"Exported history for {len(payload['history'])} vulnerabilities")

    def imp(self, path: Union[str, Path]) -> int:
        path = San.path(path, exist=True, file=True)
        try:
            payload = json.loads(FO.read(path))
        except Exception:
            raise ParseError("Invalid history JSON")

        imported = 0
        with self._lock:
            history_data = payload.get("history", {})
            for vid, entries in history_data.items():
                try:
                    vid = San.vuln(vid)
                except Exception:
                    continue
                slot = self._h[vid]
                for entry_data in entries:
                    try:
                        entry = Hist.from_dict(entry_data)
                    except Exception:
                        continue
                    if any(existing.chk == entry.chk for existing in slot):
                        continue
                    slot.append(entry)
                    imported += 1
                slot.sort(key=lambda e: e.ts)
        LOG.i(f"Imported {imported} history entries")
        return imported


# ──────────────────────────────────────────────────────────────────────────────
# BOILERPLATE
# ──────────────────────────────────────────────────────────────────────────────


class BP:
    """Status-aware boilerplate manager."""

    DEFAULTS: Dict[str, Dict[str, str]] = {
        "NotAFinding": {
            "find": (
                "Assessment Date: {date}\n"
                "Assessed By: {who}\n"
                "Asset: {asset}\n"
                "\n"
                "Verification Method:\n"
                "{verify}\n"
                "\n"
                "Evidence:\n"
                "{evid}\n"
                "\n"
                "Compliance Statement:\n"
                "{statement}\n"
                "\n"
                "Additional Notes:\n"
                "{notes}"
            ),
            "comm": "✔ Verified compliant on {date} by {who}",
        },
        "Open": {
            "find": (
                "Assessment Date: {date}\n"
                "Assessed By: {who}\n"
                "Asset: {asset}\n"
                "Severity: {severity}\n"
                "\n"
                "Deficiency Description:\n"
                "{deficiency}\n"
                "\n"
                "Security Impact:\n"
                "{impact}\n"
                "\n"
                "Recommended Remediation:\n"
                "{remediation}\n"
                "\n"
                "POA&M Information:\n"
                "  ID: {poam}\n"
                "  Status: {poam_status}\n"
                "  Target Date: {target}\n"
                "  Responsible Party: {owner}"
            ),
            "comm": "✘ Open finding. POA&M: {poam}",
        },
        "Not_Reviewed": {
            "find": (
                "Scheduled: {scheduled}\n"
                "Assigned To: {assigned}\n"
                "Priority: {priority}\n"
                "\n"
                "Assessment Plan:\n"
                "{plan}"
            ),
            "comm": "⏳ Pending assessment",
        },
        "Not_Applicable": {
            "find": (
                "Assessment Date: {date}\n"
                "Assessed By: {who}\n"
                "Asset: {asset}\n"
                "\n"
                "Justification:\n"
                "{justification}\n"
                "\n"
                "Approval:\n"
                "  Approved By: {approver}\n"
                "  Approval Date: {approval_date}"
            ),
            "comm": "N/A - {justification}",
        },
    }

    def __init__(self, custom: Optional[Union[str, Path]] = None) -> None:
        self._templates = {k: v.copy() for k, v in self.DEFAULTS.items()}
        if not custom and Cfg.BOILERPLATE_FILE and Cfg.BOILERPLATE_FILE.exists():
            custom = Cfg.BOILERPLATE_FILE
        if custom:
            with suppress(Exception):
                self._load(San.path(custom, exist=True, file=True))

    def _load(self, path: Path) -> None:
        data = json.loads(FO.read(path))
        for status, tpl in data.items():
            if status not in Sch.STAT_VALS:
                continue
            if not isinstance(tpl, dict):
                continue
            entry = self._templates.setdefault(status, {})
            if "find" in tpl and isinstance(tpl["find"], str):
                entry["find"] = tpl["find"]
            if "comm" in tpl and isinstance(tpl["comm"], str):
                entry["comm"] = tpl["comm"]
        LOG.i(f"Boilerplate templates loaded from {path}")

    def find(self, status: str, **kwargs) -> str:
        try:
            status = San.status(status)
        except Exception:
            status = "Not_Reviewed"
        template = self._templates.get(status, {}).get("find", "")
        if not template:
            return ""
        defaults = {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "who": os.getenv("USER") or os.getenv("USERNAME") or "System",
            "asset": "[Asset]",
            "verify": "[Verification Method]",
            "evid": "[Evidence]",
            "statement": "[Compliance Statement]",
            "notes": "[Notes]",
            "severity": "medium",
            "deficiency": "[Deficiency]",
            "impact": "[Impact]",
            "remediation": "[Remediation]",
            "poam": "[POA&M]",
            "poam_status": "[Status]",
            "target": "[Target Date]",
            "owner": "[Responsible Party]",
            "scheduled": "[Date]",
            "assigned": "[Assignee]",
            "priority": "[Priority]",
            "plan": "[Assessment Plan]",
            "justification": "[Justification]",
            "approver": "[Approver]",
            "approval_date": "[Approval Date]",
        }
        defaults.update(kwargs)
        with suppress(Exception):
            return template.format(**defaults)
        return template

    def comm(self, status: str, **kwargs) -> str:
        try:
            status = San.status(status)
        except Exception:
            status = "Not_Reviewed"
        template = self._templates.get(status, {}).get("comm", "")
        if not template:
            return ""
        defaults = {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "who": os.getenv("USER") or os.getenv("USERNAME") or "System",
            "justification": "[Justification]",
            "poam": "[POA&M]",
        }
        defaults.update(kwargs)
        with suppress(Exception):
            return template.format(**defaults)
        return template

    def export(self, path: Union[str, Path]) -> None:
        path = San.path(path, mkpar=True)
        with FO.atomic(path) as handle:
            json.dump(self._templates, handle, indent=2, ensure_ascii=False)
        LOG.i(f"Boilerplate templates exported to {path}")

    def imp(self, path: Union[str, Path]) -> None:
        self._load(San.path(path, exist=True, file=True))


# ──────────────────────────────────────────────────────────────────────────────
# VALIDATOR
# ──────────────────────────────────────────────────────────────────────────────


class Val:
    """Checklist validator."""

    def validate(self, path: Union[str, Path]) -> Tuple[bool, List[str], List[str], List[str]]:
        errors: List[str] = []
        warnings_: List[str] = []
        info: List[str] = []

        try:
            path = San.path(path, exist=True, file=True)
        except Exception as exc:
            return False, [str(exc)], [], []

        try:
            tree = FO.parse_xml(path)
            root = tree.getroot()
        except Exception as exc:
            return False, [f"Unable to parse XML: {exc}"], [], []

        if root.tag != Sch.ROOT:
            errors.append(f"Root element must be '{Sch.ROOT}', found '{root.tag}'")

        asset = root.find("ASSET")
        if asset is None:
            errors.append("Missing ASSET element")
        else:
            self._validate_asset(asset, errors, warnings_)

        stigs = root.find("STIGS")
        if stigs is None:
            errors.append("Missing STIGS element")
        else:
            e, w, i = self._validate_stigs(stigs)
            errors.extend(e)
            warnings_.extend(w)
            info.extend(i)

        return len(errors) == 0, errors, warnings_, info

    def _validate_asset(self, asset, errors: List[str], warnings_: List[str]) -> None:
        values = {child.tag: (child.text or "") for child in asset}
        required = ["ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "TARGET_KEY", "WEB_OR_DATABASE"]
        for field in required:
            if field not in values:
                errors.append(f"Missing ASSET field: {field}")

        marking = values.get("MARKING", "")
        if marking and marking not in Sch.MARKS:
            warnings_.append(f"Non-standard MARKING: {marking}")

        web = values.get("WEB_OR_DATABASE", "")
        if web and web not in ("true", "false"):
            errors.append("WEB_OR_DATABASE must be 'true' or 'false'")

    def _validate_stigs(self, stigs) -> Tuple[List[str], List[str], List[str]]:
        errors: List[str] = []
        warnings_: List[str] = []
        info: List[str] = []

        istigs = stigs.findall("iSTIG")
        if not istigs:
            errors.append("No iSTIG elements present")
            return errors, warnings_, info

        total_vulns = 0
        status_counts = defaultdict(int)

        for idx, istig in enumerate(istigs, 1):
            stig_info = istig.find("STIG_INFO")
            if stig_info is None:
                errors.append(f"iSTIG #{idx}: Missing STIG_INFO")
                continue

            vulns = istig.findall("VULN")
            total_vulns += len(vulns)

            for vuln in vulns:
                status = vuln.find("STATUS")
                if status is not None and status.text:
                    status_counts[status.text.strip()] += 1

        info.append(f"Total vulnerabilities: {total_vulns}")
        if total_vulns:
            reviewed = sum(
                status_counts[s]
                for s in status_counts
                if s not in ("Not_Reviewed", "")
            )
            pct = reviewed * 100 / total_vulns
            info.append(f"Reviewed: {reviewed}/{total_vulns} ({pct:.1f}%)")
            for status, count in sorted(status_counts.items()):
                info.append(f"  {status or '[empty]'}: {count}")

        return errors, warnings_, info


# ──────────────────────────────────────────────────────────────────────────────
# PROCESSOR (XCCDF ➜ CKL, CKL merge)
# ──────────────────────────────────────────────────────────────────────────────


class Proc:
    """Checklist processor."""

    def __init__(self, history: Optional[HistMgr] = None, boiler: Optional[BP] = None):
        self.history = history or HistMgr()
        self.boiler = boiler or BP()
        self.validator = Val()

    # ---------------------------------------------------------------- xccdf->ckl
    def xccdf_to_ckl(
        self,
        xccdf: Union[str, Path],
        out: Union[str, Path],
        asset: str,
        *,
        ip: str = "",
        mac: str = "",
        role: str = "None",
        marking: str = "CUI",
        dry: bool = False,
        apply_boilerplate: bool = False,
    ) -> Dict[str, Any]:
        try:
            xccdf = San.path(xccdf, exist=True, file=True)
            out = San.path(out, mkpar=True)
            asset = San.asset(asset)
            ip = San.ip(ip) if ip else ""
            mac = San.mac(mac) if mac else ""
            role = role or "None"
            marking = marking or "CUI"
        except Exception as exc:
            raise ValidationError(f"Input validation failed: {exc}") from exc

        LOG.ctx(op="xccdf_to_ckl", asset=asset, file=xccdf.name)
        LOG.i("Converting XCCDF to CKL")

        try:
            tree = FO.parse_xml(xccdf)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Failed to parse XCCDF: {exc}") from exc

        ns = self._namespace(root)
        meta = self._extract_meta(root, ns)

        LOG.i(f"STIG title: {meta.get('title', 'unknown')}")
        LOG.i(f"STIG version: {meta.get('version', 'unknown')}")

        checklist = ET.Element(Sch.ROOT)
        self._build_asset(checklist, asset, ip, mac, role, marking, meta)

        stigs = ET.SubElement(checklist, "STIGS")
        istig = ET.SubElement(stigs, "iSTIG")
        self._build_stig_info(istig, xccdf, meta)

        groups = self._list_groups(root, ns)
        if not groups:
            raise ParseError("XCCDF contains no vulnerability groups")

        if len(groups) > Cfg.MAX_VULNS:
            LOG.w(f"Large checklist: {len(groups)} vulnerabilities")

        LOG.i(f"Processing {len(groups)} vulnerabilities")

        processed = 0
        skipped = 0
        errors: List[str] = []

        for idx, group in enumerate(groups, 1):
            try:
                vuln = self._build_vuln(group, ns, meta, apply_boilerplate, asset)
                if vuln is None:
                    skipped += 1
                else:
                    istig.append(vuln)
                    processed += 1
            except Exception as exc:
                errors.append(str(exc))
                skipped += 1
                LOG.e(f"Group {idx} failed: {exc}")

        if processed == 0:
            raise ParseError("No vulnerabilities could be processed")

        LOG.i(f"Processed: {processed} | Skipped: {skipped}")

        self._indent_xml(checklist)

        if dry:
            LOG.i("Dry-run requested, checklist not written")
            LOG.clear()
            return {"ok": True, "processed": processed, "skipped": skipped, "errors": errors}

        self._write_ckl(checklist, out)

        try:
            ok, errs, _, _ = self.validator.validate(out)
            if not ok:
                raise ValidationError(f"Generated CKL failed validation: {errs[0] if errs else 'Unknown error'}")
        except ValidationError:
            raise
        except Exception:
            pass  # Do not block output if validator crashes

        LOG.i(f"Checklist created: {out}")
        LOG.clear()
        return {"ok": True, "output": str(out), "processed": processed, "skipped": skipped, "errors": errors}

    # ------------------------------------------------------------------- helpers
    def _namespace(self, root: Any) -> Dict[str, str]:
        if "}" in root.tag:
            uri = root.tag.split("}")[0][1:]
            return {"ns": uri}
        return {}

    def _extract_meta(self, root, ns: Dict[str, str]) -> Dict[str, str]:
        meta = {
            "title": "Unknown STIG",
            "description": "",
            "version": "1",
            "stigid": root.get("id", "Unknown_STIG"),
            "releaseinfo": f"Release: 1 Benchmark Date: {datetime.now(timezone.utc).strftime('%d %b %Y')}",
            "classification": "UNCLASSIFIED",
            "source": "STIG.DOD.MIL",
            "target_key": "2350",
        }

        def find_text(tag: str, default: str = "") -> str:
            search_tag = f"ns:{tag}" if ns else tag
            element = root.find(search_tag, ns)
            if element is not None and element.text:
                return element.text.strip()
            return default

        meta["title"] = find_text("title", meta["title"])
        meta["description"] = find_text("description", meta["title"])
        meta["version"] = find_text("version", meta["version"])

        plain = root.find('plain-text[@id="release-info"]')
        if plain is not None and plain.text:
            meta["releaseinfo"] = plain.text.strip()

        ref_search = ".//ns:reference" if ns else ".//reference"
        for reference in root.findall(ref_search, ns):
            for sub in reference:
                tag_name = sub.tag.split("}")[-1]
                if "identifier" in tag_name.lower() and sub.text:
                    meta["target_key"] = sub.text.strip()
                    break

        return meta

    def _build_asset(
        self,
        parent,
        asset: str,
        ip: str,
        mac: str,
        role: str,
        marking: str,
        meta: Dict[str, str],
    ) -> None:
        asset_node = ET.SubElement(parent, "ASSET")
        values = {
            "ROLE": role,
            "ASSET_TYPE": "Computing",
            "MARKING": marking,
            "HOST_NAME": asset,
            "HOST_IP": ip,
            "HOST_MAC": mac,
            "HOST_FQDN": asset,
            "TARGET_COMMENT": "",
            "TECH_AREA": "",
            "TARGET_KEY": meta.get("target_key", "2350"),
            "WEB_OR_DATABASE": "false",
            "WEB_DB_SITE": "",
            "WEB_DB_INSTANCE": "",
        }
        for field in Sch.ASSET:
            node = ET.SubElement(asset_node, field)
            node.text = values.get(field, "")

    def _build_stig_info(self, parent, xccdf: Path, meta: Dict[str, str]) -> None:
        stig_info = ET.SubElement(parent, "STIG_INFO")
        values = {
            "version": meta.get("version", "1"),
            "classification": meta.get("classification", "UNCLASSIFIED"),
            "customname": "",
            "stigid": meta.get("stigid", "Unknown_STIG"),
            "description": meta.get("description", ""),
            "filename": xccdf.name if hasattr(xccdf, "name") else str(xccdf),
            "releaseinfo": meta.get("releaseinfo", ""),
            "title": meta.get("title", ""),
            "uuid": str(uuid.uuid4()),
            "notice": "terms-of-use",
            "source": meta.get("source", "STIG.DOD.MIL"),
        }

        for field in Sch.STIG:
            si_data = ET.SubElement(stig_info, "SI_DATA")
            name = ET.SubElement(si_data, "SID_NAME")
            name.text = field
            data = ET.SubElement(si_data, "SID_DATA")
            value = values.get(field, "")
            if value:
                data.text = value

    def _list_groups(self, root, ns: Dict[str, str]) -> List[Any]:
        search = ".//ns:Group" if ns else ".//Group"
        groups = root.findall(search, ns)
        valid: List[Any] = []
        for group in groups:
            rule = group.find("ns:Rule", ns) if ns else group.find("Rule")
            if rule is not None:
                valid.append(group)
        return valid

    def _build_vuln(
        self,
        group,
        ns: Dict[str, str],
        meta: Dict[str, str],
        apply_boilerplate: bool,
        asset: str,
    ):
        vid = group.get("id", "")
        if not vid:
            return None
        try:
            vid = San.vuln(vid)
        except Exception:
            return None

        rule = group.find("ns:Rule", ns) if ns else group.find("Rule")
        if rule is None:
            return None

        rule_id = rule.get("id", "").strip()
        if not rule_id:
            return None

        severity = San.sev(rule.get("severity", "medium"))
        weight = rule.get("weight", "10.0")

        def find(tag: str):
            return rule.find(f"ns:{tag}", ns) if ns else rule.find(tag)

        def findall(tag: str):
            return rule.findall(f"ns:{tag}", ns) if ns else rule.findall(tag)

        def text(elem) -> str:
            if elem is None:
                return ""
            if elem.text and elem.text.strip():
                return elem.text.strip()
            try:
                return ET.tostring(elem, encoding="unicode", method="text").strip()
            except Exception as exc:
                LOG.w(f"Failed to extract text from XML element {elem.tag}: {exc}")
                return ""

        rule_title = text(find("title"))[:300]
        rule_ver = text(find("version"))
        discussion = text(find("description"))
        fix_elem = find("fixtext")

        fix_text = self._collect_fix_text(fix_elem) if fix_elem is not None else ""

        check_elem = find("check")
        check_text = ""
        check_ref = "M"
        if check_elem is not None:
            check_content = check_elem.find("ns:check-content", ns) if ns else check_elem.find("check-content")
            check_text = self._collect_fix_text(check_content) if check_content is not None else ""
            check_content_ref = check_elem.find("ns:check-content-ref", ns) if ns else check_elem.find("check-content-ref")
            if check_content_ref is not None:
                ref_name = check_content_ref.get("name", "M")
                if ref_name:
                    check_ref = ref_name

        group_title_elem = group.find("ns:title", ns) if ns else group.find("title")
        group_title = text(group_title_elem) if group_title_elem is not None else vid

        legacy_refs: List[str] = []
        cci_refs: List[str] = []

        for ident in findall("ident"):
            ident_text = text(ident)
            if not ident_text:
                continue
            system = (ident.get("system") or "").lower()
            if "cci" in system:
                cci_refs.append(ident_text)
            elif "legacy" in system:
                legacy_refs.append(ident_text)

        vuln_node = ET.Element("VULN")
        stig_data_map = OrderedDict(
            [
                ("Vuln_Num", vid),
                ("Severity", severity),
                ("Group_Title", group_title),
                ("Rule_ID", rule_id),
                ("Rule_Ver", rule_ver),
                ("Rule_Title", rule_title),
                ("Vuln_Discuss", discussion),
                ("IA_Controls", ""),
                ("Check_Content", check_text),
                ("Fix_Text", fix_text),
                ("False_Positives", ""),
                ("False_Negatives", ""),
                ("Documentable", "false"),
                ("Mitigations", ""),
                ("Potential_Impact", ""),
                ("Third_Party_Tools", ""),
                ("Mitigation_Control", ""),
                ("Responsibility", ""),
                ("Security_Override_Guidance", ""),
                ("Check_Content_Ref", check_ref),
                ("Weight", weight),
                ("Class", "Unclass"),
                (
                    "STIGRef",
                    f"{meta.get('title', '')} :: Version {meta.get('version', '')}, "
                    f"{meta.get('releaseinfo', '')}",
                ),
                ("TargetKey", meta.get("target_key", "2350")),
                ("STIG_UUID", str(uuid.uuid4())),
            ]
        )

        for attribute in Sch.VULN:
            value = stig_data_map.get(attribute, "")
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = attribute
            data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            if value:
                data.text = San.xml(value)

        for legacy in legacy_refs:
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = "LEGACY_ID"
            data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            data.text = legacy

        for cci in cci_refs:
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = "CCI_REF"
            data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            data.text = cci

        status = "Not_Reviewed"
        finding = ""
        comment = ""

        if apply_boilerplate:
            finding = self.boiler.find(status, asset=asset, severity=severity)
            comment = self.boiler.comm(status)

        status_node = ET.SubElement(vuln_node, "STATUS")
        status_node.text = status
        finding_node = ET.SubElement(vuln_node, "FINDING_DETAILS")
        if finding:
            finding_node.text = finding
        comment_node = ET.SubElement(vuln_node, "COMMENTS")
        if comment:
            comment_node.text = comment
        ET.SubElement(vuln_node, "SEVERITY_OVERRIDE")
        ET.SubElement(vuln_node, "SEVERITY_JUSTIFICATION")

        return vuln_node

    def _collect_fix_text(self, elem) -> str:
        """
        Enhanced fix text extraction with proper handling of XCCDF mixed content.

        Handles:
        - Plain text content
        - Nested HTML elements (xhtml:br, xhtml:code, etc.)
        - CDATA sections
        - Mixed content with proper whitespace preservation
        """
        if elem is None:
            return ""

        # Method 1: itertext() with proper newline preservation
        try:
            parts: List[str] = []
            # Collect all text including from nested elements
            for text_fragment in elem.itertext():
                if text_fragment:
                    # Only strip leading/trailing whitespace, preserve internal structure
                    cleaned = text_fragment.strip()
                    if cleaned:
                        parts.append(cleaned)

            if parts:
                # Join with newlines to preserve command structure
                result = '\n'.join(parts)
                # Clean up excessive blank lines but keep structure
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"itertext() extraction failed: {exc}")

        # Method 2: Manual traversal for complex mixed content
        try:
            def extract_text_recursive(element) -> List[str]:
                texts = []
                if element.text:
                    txt = element.text.strip()
                    if txt:
                        texts.append(txt)
                for child in element:
                    # Recursively get text from children
                    texts.extend(extract_text_recursive(child))
                    # Get tail text (text after child element)
                    if child.tail:
                        tail = child.tail.strip()
                        if tail:
                            texts.append(tail)
                return texts

            parts = extract_text_recursive(elem)
            if parts:
                result = '\n'.join(parts)
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"Recursive extraction failed: {exc}")

        # Method 3: Direct text attribute (simple elements only)
        if elem.text and elem.text.strip():
            return elem.text.strip()

        # Method 4: Last resort - tostring
        try:
            text_content = ET.tostring(elem, encoding='unicode', method='text')
            if text_content and text_content.strip():
                # Clean up excessive whitespace
                text_content = re.sub(r'\s+', ' ', text_content)
                return text_content.strip()
        except Exception as exc:
            LOG.d(f"tostring() extraction failed: {exc}")

        return ""




    def _indent_xml(self, elem, level: int = 0) -> None:
        indent = "\n" + "\t" * level
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = indent + "\t"
            for i, child in enumerate(elem):
                self._indent_xml(child, level + 1)
                if not child.tail or not child.tail.strip():
                    # Last child gets dedented, others get full indent
                    child.tail = indent if i == len(elem) - 1 else indent + "\t"
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = indent

    def _write_ckl(self, root, out: Path) -> None:
        try:
            with FO.atomic(out, mode="wb", bak=False) as handle:
                handle.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                handle.write(f"<!--{Sch.COMMENT}-->\n".encode("utf-8"))
                xml_text = ET.tostring(root, encoding="unicode", method="xml")
                handle.write(xml_text.encode("utf-8"))
        except Exception as exc:
            raise FileError(f"Failed to write CKL: {exc}") from exc

    # -------------------------------------------------------------------- merge
    def merge(
        self,
        base: Union[str, Path],
        histories: Iterable[Union[str, Path]],
        out: Union[str, Path],
        *,
        preserve_history: bool = True,
        apply_boilerplate: bool = True,
        dry: bool = False,
    ) -> Dict[str, Any]:
        try:
            base = San.path(base, exist=True, file=True)
            out = San.path(out, mkpar=True)
            history_paths = [San.path(p, exist=True, file=True) for p in histories]
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        if len(history_paths) > Cfg.MAX_MERGE:
            raise ValidationError(f"Too many historical files (limit {Cfg.MAX_MERGE})")

        LOG.ctx(op="merge", base=base.name, histories=len(history_paths))
        LOG.i(f"Merging {len(history_paths)} checklist(s) into base {base.name}")

        if preserve_history:
            for idx, hist_file in enumerate(history_paths, 1):
                LOG.d(f"Loading history {idx}/{len(history_paths)}: {hist_file}")
                self._ingest_history(hist_file)

        try:
            tree = FO.parse_xml(base)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Unable to parse base checklist: {exc}") from exc

        if root.tag != Sch.ROOT:
            raise ParseError("Base checklist has incorrect root element")

        stigs = root.find("STIGS")
        if stigs is None:
            raise ParseError("Base checklist missing STIGS")

        total_vulns = sum(len(istig.findall("VULN")) for istig in stigs.findall("iSTIG"))
        if total_vulns == 0:
            raise ParseError("Base checklist contains no vulnerabilities")

        updated = 0
        skipped = 0

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                result = self._merge_vuln(vuln, preserve_history, apply_boilerplate)
                if result is True:
                    updated += 1
                else:
                    skipped += 1

        LOG.i(f"Merge summary: {updated} updated, {skipped} unchanged")

        self._indent_xml(root)

        if dry:
            LOG.i("Dry-run requested, merged checklist not written")
            LOG.clear()
            return {"updated": updated, "skipped": skipped, "dry_run": True}

        self._write_ckl(root, out)
        LOG.i(f"Merged checklist saved to {out}")
        LOG.clear()
        return {"updated": updated, "skipped": skipped, "dry_run": False, "output": str(out)}

    # ----------------------------------------------------------------- helpers
    def _ingest_history(self, path: Path) -> None:
        try:
            tree = FO.parse_xml(path)
            root = tree.getroot()
        except Exception:
            return

        stigs = root.find("STIGS")
        if stigs is None:
            return

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = self._get_vid(vuln)
                if not vid:
                    continue

                status = vuln.findtext("STATUS", default="Not_Reviewed")
                finding = vuln.findtext("FINDING_DETAILS", default="")
                comment = vuln.findtext("COMMENTS", default="")
                severity = "medium"

                for sd in vuln.findall("STIG_DATA"):
                    attr = sd.findtext("VULN_ATTRIBUTE")
                    if attr == "Severity":
                        severity = San.sev(sd.findtext("ATTRIBUTE_DATA", "medium"))

                if finding.strip() or comment.strip():
                    self.history.add(
                        vid,
                        status,
                        finding,
                        comment,
                        src=path.name,
                        sev=severity,
                    )

    def _get_vid(self, vuln) -> Optional[str]:
        for sd in vuln.findall("STIG_DATA"):
            attr = sd.findtext("VULN_ATTRIBUTE")
            if attr == "Vuln_Num":
                vid = sd.findtext("ATTRIBUTE_DATA")
                if vid:
                    with suppress(Exception):
                        return San.vuln(vid.strip())
        return None

    def _merge_vuln(self, vuln, preserve_history: bool, apply_boilerplate: bool) -> bool:
        vid = self._get_vid(vuln)
        if not vid:
            return False

        status_node = vuln.find("STATUS")
        status = status_node.text.strip() if status_node is not None and status_node.text else "Not_Reviewed"
        finding_node = vuln.find("FINDING_DETAILS")
        comment_node = vuln.find("COMMENTS")

        current_finding = finding_node.text if finding_node is not None and finding_node.text else ""
        current_comment = comment_node.text if comment_node is not None and comment_node.text else ""

        merged = False

        if preserve_history and vid in self.history._h:
            merged_finding = self.history.merge_find(vid, current_finding)
            if finding_node is None:
                finding_node = ET.SubElement(vuln, "FINDING_DETAILS")
            finding_node.text = merged_finding

            merged_comment = self.history.merge_comm(vid, current_comment)
            if comment_node is None:
                comment_node = ET.SubElement(vuln, "COMMENTS")
            comment_node.text = merged_comment

            merged = True

        elif apply_boilerplate and status in Sch.STAT_VALS:
            default_finding = self.boiler.find(status)
            default_comment = self.boiler.comm(status)
            if default_finding and not current_finding.strip():
                if finding_node is None:
                    finding_node = ET.SubElement(vuln, "FINDING_DETAILS")
                finding_node.text = default_finding
                merged = True
            if default_comment and not current_comment.strip():
                if comment_node is None:
                    comment_node = ET.SubElement(vuln, "COMMENTS")
                comment_node.text = default_comment
                merged = True

        return merged


# ──────────────────────────────────────────────────────────────────────────────
# FIX EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Fix:
    vid: str
    rule_id: str
    severity: str
    title: str
    group_title: str
    fix_text: str
    fix_command: Optional[str] = None
    check_command: Optional[str] = None
    platform: str = "generic"
    rule_version: str = ""
    cci: List[str] = field(default_factory=list)
    legacy: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "vid": self.vid,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title[:200],
            "group_title": self.group_title,
            "fix_text": self.fix_text,
            "fix_command": self.fix_command,
            "check_command": self.check_command,
            "platform": self.platform,
            "rule_version": self.rule_version,
            "cci": self.cci[:10],
            "legacy": self.legacy[:10],
        }


class FixExt:
    """Fix extractor with enhanced command parsing."""

    CODE_BLOCK = re.compile(r"```(?:bash|sh|shell|zsh|powershell|ps1|ps|cmd|bat)\s*(.*?)```", re.DOTALL | re.IGNORECASE)
    TRIPLE_TICK = re.compile(r"```(.*?)```", re.DOTALL)
    SHELL_PROMPT = re.compile(r"(?m)^(?:\$|#|>)\s*(.+)")
    POWERSHELL_PROMPT = re.compile(r"(?m)^(?:PS [^>]+>|\w:\\[^>]*>)\s*(.+)")
    BULLET_CMD = re.compile(r"(?m)^(?:[-*+]|\d+\.)\s*(?:Run|Execute)\s*[:\-]?\s*(.+)")
    INLINE_CMD = re.compile(r"`([^`]+)`")
    COMMAND_LINE = re.compile(r"(?m)^\s*(?:#|sudo)\s+(.+)$")
    PLAIN_COMMAND = re.compile(r"(?:run|execute|use)\s+(?:the\s+)?(?:following\s+)?(?:command|commands?)[\s:]+(.+?)(?:\n|$)", re.IGNORECASE)
    CONFIG_FILE = re.compile(r"(?:edit|modify|update)\s+(?:the\s+)?(?:file\s+)?([/\w.-]+(?:/[\w.-]+)*)", re.IGNORECASE)
    SCRIPT_BLOCK = re.compile(r"(?:#!/bin/(?:bash|sh)|@echo off)(.*?)(?=\n\n|\Z)", re.DOTALL)
    SERVICE_CMD = re.compile(r"^\s*(?:systemctl|service)\s+(?:start|stop|restart|enable|disable|status)\s+\S+", re.MULTILINE)
    AUDIT_CMD = re.compile(r"^\s*(?:auditctl|ausearch|aureport)\s+.+", re.MULTILINE)
    SELINUX_CMD = re.compile(r"^\s*(?:semanage|setsebool|restorecon|chcon|getenforce|setenforce)\s+.+", re.MULTILINE)


    def __init__(self, xccdf: Union[str, Path]):
        self.xccdf = San.path(xccdf, exist=True, file=True)
        self.ns: Dict[str, str] = {}
        self.fixes: List[Fix] = []
        self.stats = {
            "total_groups": 0,
            "with_fix": 0,
            "with_command": 0,
            "platforms": defaultdict(int),
        }

    # ---------------------------------------------------------------- extract
    def extract(self) -> List[Fix]:
        LOG.ctx(op="extract_fix", file=self.xccdf.name)
        LOG.i("Extracting fix information")

        try:
            tree = FO.parse_xml(self.xccdf)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Unable to parse XCCDF: {exc}") from exc

        self.ns = self._namespace(root)
        groups = self._groups(root)
        if not groups:
            raise ParseError("No vulnerability groups found in XCCDF")

        self.stats["total_groups"] = len(groups)
        for idx, group in enumerate(groups, 1):
            with suppress(Exception):
                fix = self._parse_group(group)
                if fix:
                    self.fixes.append(fix)
                    self.stats["with_fix"] += 1
                    if fix.fix_command:
                        self.stats["with_command"] += 1
                    self.stats["platforms"][fix.platform] += 1

        LOG.i(
            f"Extracted {len(self.fixes)} fixes "
            f"({self.stats['with_command']} with actionable commands)"
        )
        LOG.clear()
        return self.fixes

    # ---------------------------------------------------------------- helpers
    def _namespace(self, root: Any) -> Dict[str, str]:
        if "}" in root.tag:
            uri = root.tag.split("}")[0][1:]
            return {"ns": uri}
        return {}

    def _groups(self, root: Any) -> List[Any]:
        search = ".//ns:Group" if self.ns else ".//Group"
        groups = root.findall(search, self.ns)
        valid: List[Any] = []
        for group in groups:
            rule = group.find("ns:Rule", self.ns) if self.ns else group.find("Rule")
            if rule is not None:
                valid.append(group)
        return valid


    def _parse_group(self, group) -> Optional[Fix]:
        vid = group.get("id", "")
        if not vid:
            return None
        try:
            vid = San.vuln(vid)
        except Exception:
            return None

        rule = group.find("ns:Rule", self.ns) if self.ns else group.find("Rule")
        if rule is None:
            return None

        rule_id = rule.get("id", "unknown")
        severity = San.sev(rule.get("severity", "medium"))

        def find(tag: str):
            return rule.find(f"ns:{tag}", self.ns) if self.ns else rule.find(tag)

        def findall(tag: str):
            return rule.findall(f"ns:{tag}", self.ns) if self.ns else rule.findall(tag)

        def text(elem) -> str:
            if elem is None:
                return ""
            if elem.text and elem.text.strip():
                return elem.text.strip()
            try:
                return ET.tostring(elem, encoding="unicode", method="text").strip()
            except Exception as exc:
                LOG.w(f"Failed to extract text from XML element {elem.tag}: {exc}")
                return ""

        title = text(find("title"))
        rule_version = text(find("version"))

        group_title_elem = group.find("ns:title", self.ns) if self.ns else group.find("title")
        group_title = text(group_title_elem) if group_title_elem is not None else vid

        # Extract fix text
        fix_elem = find("fixtext")
        fix_text = ""
        if fix_elem is not None:
            fix_text = self._collect_text(fix_elem)
            if not fix_text.strip():
                LOG.w(f"{vid}: Empty fixtext extracted, checking attributes")
                fix_text = fix_elem.get('fixref', '') or fix_elem.get('id', '')

        if not fix_text.strip():
            LOG.d(f"{vid}: Skipping - no fix text available")
            return None

        # Extract check content
        check_elem = find("check")
        check_text = ""
        check_command = None
        if check_elem is not None:
            check_content = check_elem.find("ns:check-content", self.ns) if self.ns else check_elem.find("check-content")
            if check_content is not None:
                check_text = self._collect_text(check_content)
                check_command = self._extract_command(check_text)

        # Extract fix command
        fix_command = self._extract_command(fix_text)

        cci_refs: List[str] = []
        legacy_refs: List[str] = []
        for ident in findall("ident"):
            ident_text = text(ident)
            if not ident_text:
                continue
            system = (ident.get("system") or "").lower()
            if "cci" in system:
                cci_refs.append(ident_text)
            elif "legacy" in system:
                legacy_refs.append(ident_text)

        platform = self._detect_platform(fix_text, fix_command)

        return Fix(
            vid=vid,
            rule_id=rule_id,
            severity=severity,
            title=title,
            group_title=group_title,
            fix_text=fix_text,
            fix_command=fix_command,
            check_command=check_command,
            platform=platform,
            rule_version=rule_version,
            cci=cci_refs,
            legacy=legacy_refs,
        )


    def _collect_text(self, elem: Any) -> str:
        """
        Enhanced text extraction with proper mixed content handling.

        Handles XCCDF elements that contain plain text, nested elements,
        and preserves command formatting.
        """
        if elem is None:
            return ""

        # Method 1: itertext() with proper newline preservation
        try:
            parts: List[str] = []
            # Collect all text including from nested elements
            for text_fragment in elem.itertext():
                if text_fragment:
                    # Only strip leading/trailing whitespace, preserve internal structure
                    cleaned = text_fragment.strip()
                    if cleaned:
                        parts.append(cleaned)

            if parts:
                # Join with newlines to preserve command structure
                result = '\n'.join(parts)
                # Clean up excessive blank lines but keep structure
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"itertext() extraction failed: {exc}")

        # Method 2: Manual traversal for complex mixed content
        try:
            def extract_text_recursive(element) -> List[str]:
                texts = []
                if element.text:
                    txt = element.text.strip()
                    if txt:
                        texts.append(txt)
                for child in element:
                    # Recursively get text from children
                    texts.extend(extract_text_recursive(child))
                    # Get tail text (text after child element)
                    if child.tail:
                        tail = child.tail.strip()
                        if tail:
                            texts.append(tail)
                return texts

            parts = extract_text_recursive(elem)
            if parts:
                result = '\n'.join(parts)
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"Recursive extraction failed: {exc}")

        # Method 3: Direct text attribute (simple elements only)
        if elem.text and elem.text.strip():
            return elem.text.strip()

        # Method 4: Last resort - tostring
        try:
            text_content = ET.tostring(elem, encoding='unicode', method='text')
            if text_content and text_content.strip():
                # Clean up excessive whitespace
                text_content = re.sub(r'\s+', ' ', text_content)
                return text_content.strip()
        except Exception as exc:
            LOG.d(f"tostring() extraction failed: {exc}")

        return ""


    def _extract_command(self, text_block: str) -> Optional[str]:
        """
        Enhanced command extraction supporting multiple STIG fixtext formats.

        Handles:
        - Shell commands (with or without prompts)
        - PowerShell commands
        - Windows Group Policy paths
        - Configuration file edits
        - Multi-line command sequences
        - Registry modifications
        """
        text_block = text_block or ""
        if len(text_block) < 5:
            return None

        candidates: List[str] = []

        # ═══ PATTERN 1: Code blocks (markdown style) ═══
        for pattern in (self.CODE_BLOCK, self.TRIPLE_TICK):
            candidates.extend(pattern.findall(text_block))

        # ═══ PATTERN 2: Shell prompts ═══
        candidates.extend(self.SHELL_PROMPT.findall(text_block))
        candidates.extend(self.POWERSHELL_PROMPT.findall(text_block))

        # ═══ PATTERN 3: Bullet-style commands ═══
        candidates.extend(self.BULLET_CMD.findall(text_block))

        # ═══ PATTERN 4: Inline code ═══
        candidates.extend(self.INLINE_CMD.findall(text_block))

        # ═══ PATTERN 5: "Run the following command" blocks ═══
        # Matches: "Run the following command:" followed by actual commands
        run_command_pattern = re.compile(
            r"(?:run|execute|use|enter|type)\s+(?:the\s+)?(?:following\s+)?(?:command|commands?)[\s:]+\n(.+?)(?:\n\n|\Z)",
            re.IGNORECASE | re.DOTALL
        )
        for match in run_command_pattern.finditer(text_block):
            cmd_block = match.group(1).strip()
            if cmd_block and len(cmd_block) > 5:
                candidates.append(cmd_block)

        # ═══ PATTERN 6: Common Unix/Linux commands ═══
        # Matches lines with common system commands
        unix_cmd_pattern = re.compile(
            r"^\s*(?:sudo\s+)?(?:chmod|chown|chgrp|systemctl|service|grep|sed|awk|find|rpm|yum|dnf|apt-get|"
            r"apt|mount|umount|useradd|usermod|passwd|groupadd|ln|cp|mv|rm|mkdir|touch|cat|echo|vi|nano|"
            r"gsettings|dconf|auditctl|ausearch|aureport|restorecon|semanage|setsebool|firewall-cmd)\s+.+",
            re.MULTILINE
        )
        candidates.extend(unix_cmd_pattern.findall(text_block))

        # ═══ PATTERN 7: PowerShell cmdlets ═══
        # Matches PowerShell commands
        ps_cmdlet_pattern = re.compile(
            r"^\s*(?:Set-|Get-|New-|Remove-|Add-|Enable-|Disable-|Test-|Invoke-)[A-Za-z]+(?:\s+-[A-Za-z]+\s+[^\n]+)+",
            re.MULTILINE
        )
        candidates.extend(ps_cmdlet_pattern.findall(text_block))

        # ═══ PATTERN 8: Registry commands (Windows) ═══
        # Matches reg.exe commands
        reg_cmd_pattern = re.compile(
            r"^\s*reg(?:\.exe)?\s+(?:add|delete|query|import|export)\s+.+",
            re.MULTILINE | re.IGNORECASE
        )
        candidates.extend(reg_cmd_pattern.findall(text_block))

        # ═══ PATTERN 9: File editing instructions ═══
        # Matches "Edit the file /path/to/file" and extracts the file path
        edit_file_pattern = re.compile(
            r"(?:edit|modify|update|change)\s+(?:the\s+)?(?:file|configuration)\s+([/\w.-]+(?:/[\w.-]+)*)",
            re.IGNORECASE
        )
        for match in edit_file_pattern.finditer(text_block):
            file_path = match.group(1)
            # Create a simple edit command
            candidates.append(f"# Edit file: {file_path}\nvi {file_path}")

        # ═══ PATTERN 10: Windows Group Policy paths ═══
        # These aren't executable but are important configuration instructions
        gpo_pattern = re.compile(
            r"(?:Computer Configuration|User Configuration)\s*>>?\s*.+?(?:>>?\s*.+?)*",
            re.IGNORECASE
        )
        gpo_matches = gpo_pattern.findall(text_block)
        if gpo_matches:
            # Format as a configuration instruction
            for gpo_path in gpo_matches:
                clean_path = gpo_path.replace('>>', '\\').strip()
                candidates.append(f"# Group Policy:\n# {clean_path}")

        # ═══ PATTERN 11: Multi-line command blocks ═══
        # Matches blocks that look like shell scripts (multiple lines with commands)
        multiline_pattern = re.compile(
            r"(?:^|\n)((?:(?:sudo\s+)?(?:\w+(?:/\w+)*|\w+)\s+[^\n]+\n?){2,})",
            re.MULTILINE
        )
        for match in multiline_pattern.finditer(text_block):
            block = match.group(1).strip()
            # Verify it looks like commands (has common command words)
            if any(cmd in block for cmd in ['chmod', 'chown', 'systemctl', 'grep', 'sed', 'echo', 'Set-', 'Get-']):
                candidates.append(block)

        # ═══ PATTERN 12: Commands after colons ═══
        # Matches: "Command: something" or "Solution: do this"
        colon_cmd_pattern = re.compile(
            r"(?:Command|Solution|Fix|Remediation|Action):\s*\n?(.+?)(?:\n\n|\Z)",
            re.IGNORECASE | re.DOTALL
        )
        for match in colon_cmd_pattern.finditer(text_block):
            cmd = match.group(1).strip()
            if len(cmd) > 5 and len(cmd) < 500:  # Reasonable command length
                candidates.append(cmd)

        # ═══ CLEANUP: Remove comments, filter, and deduplicate ═══
        commands: List[str] = []
        seen = set()

        for cand in candidates:
            if isinstance(cand, tuple):
                cand = cand[-1]

            # Clean up the command
            lines = []
            for line in cand.strip().splitlines():
                line = line.strip()
                # Skip empty lines and pure comment lines
                if not line or (line.startswith('#') and not any(cmd in line for cmd in ['chmod', 'chown', 'Edit'])):
                    continue
                lines.append(line)

            cmd = '\n'.join(lines)

            # Validation: must meet minimum criteria
            if len(cmd) < 5:
                continue
            if len(cmd) > 2000:  # Too long, probably not a command
                continue

            # Deduplicate
            cmd_hash = hashlib.md5(cmd.encode()).hexdigest()
            if cmd_hash in seen:
                continue
            seen.add(cmd_hash)

            commands.append(cmd)

        if not commands:
            return None

        # Return the longest/most substantial command
        return max(commands, key=lambda x: len(x)).strip()


    def _detect_platform(self, text_block: str, cmd: Optional[str]) -> str:
        combined = f"{text_block}\n{cmd or ''}".lower()
        if any(token in combined for token in ("powershell", "set-mdp", "new-item", "registry", "gpo", "windows")):
            return "windows"
        if any(token in combined for token in ("systemctl", "chmod", "chown", "/etc/", "apt-get", "yum", "dnf", "rpm", "bash")):
            return "linux"
        if any(token in combined for token in ("cisco", "ios", "switchport", "interface", "router", "show running-config")):
            return "network"
        return "generic"

    # ---------------------------------------------------------------- export
    def to_json(self, path: Union[str, Path]) -> None:
        path = San.path(path, mkpar=True)
        payload = {
            "meta": {
                "source": str(self.xccdf),
                "generated": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
                "stats": {
                    "total_groups": self.stats["total_groups"],
                    "with_fix": self.stats["with_fix"],
                    "with_command": self.stats["with_command"],
                    "platforms": dict(self.stats["platforms"]),
                },
            },
            "fixes": [fix.as_dict() for fix in self.fixes],
        }
        with FO.atomic(path) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        LOG.i(f"Fixes exported to JSON: {path}")

    def to_csv(self, path: Union[str, Path]) -> None:
        path = San.path(path, mkpar=True)
        with FO.atomic(path) as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "Vuln_ID",
                    "Rule_ID",
                    "Severity",
                    "Title",
                    "Group_Title",
                    "Platform",
                    "Has_Fix_Command",
                    "Has_Check_Command",
                    "Fix_Command",
                    "Check_Command",
                    "CCI",
                ]
            )
            for fix in self.fixes:
                writer.writerow(
                    [
                        fix.vid,
                        fix.rule_id,
                        fix.severity,
                        fix.title[:120],
                        fix.group_title[:80],
                        fix.platform,
                        "Yes" if fix.fix_command else "No",
                        "Yes" if fix.check_command else "No",
                        (fix.fix_command or "")[:500],
                        (fix.check_command or "")[:200],
                        "; ".join(fix.cci[:5]),
                    ]
                )
        LOG.i(f"Fixes exported to CSV: {path}")

    def to_bash(self, path: Union[str, Path], severity_filter: Optional[List[str]] = None, dry_run: bool = False) -> None:
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.fix_command and fix.platform in ("linux", "generic") and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Linux/generic fixes with commands found")
            return

        lines: List[str] = [
            "#!/usr/bin/env bash",
            "# Auto-generated remediation script",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Mode: {'DRY RUN' if dry_run else 'LIVE'}",
            "",
            "set -euo pipefail",
            "",
            "DRY_RUN=" + ("1" if dry_run else "0"),
            "LOG_FILE=\"stig_fix_$(date +%Y%m%d_%H%M%S).log\"",
            "RESULT_FILE=\"stig_results_$(date +%Y%m%d_%H%M%S).json\"",
            "",
            "echo \"Remediation started\" | tee -a \"$LOG_FILE\"",
            "declare -i PASS=0 FAIL=0 SKIP=0",
            "declare -a RESULTS=()",
            "",
            "record_result() {",
            "  local vid=\"$1\"",
            "  local ok=\"$2\"",
            "  local msg=\"$3\"",
            "  RESULTS+=('{\"vid\":\"'\"$vid\"'\",\"ok\":'\"$ok\"',\"msg\":\"'\"${msg//\"/\\\"}\"'\",\"ts\":\"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\"}')",
            "}",
            "",
        ]

        for idx, fix in enumerate(fixes, 1):
            safe_vid = re.sub(r"[^A-Za-z0-9_]", "_", fix.vid)
            lines.append(f"echo \"[{idx}/{len(fixes)}] {fix.vid} - {fix.title[:60]}\" | tee -a \"$LOG_FILE\"")
            if dry_run:
                lines.append(f"echo \"  [DRY-RUN] Would execute:\n{fix.fix_command}\" | tee -a \"$LOG_FILE\"")
                lines.append(f"record_result \"{fix.vid}\" true \"dry_run\"")
                lines.append("((PASS++))")
                lines.append("")
                continue

            lines.append(
                "{\n" + "\n".join(f"  {line}" for line in fix.fix_command.splitlines()) + "\n} >>\"$LOG_FILE\" 2>&1"
            )
            lines.append("if [ $? -eq 0 ]; then")
            lines.append("  echo \"  ✔ Success\" | tee -a \"$LOG_FILE\"")
            lines.append(f"  record_result \"{fix.vid}\" true \"success\"")
            lines.append("  ((PASS++))")
            lines.append("else")
            lines.append("  echo \"  ✘ Failed\" | tee -a \"$LOG_FILE\"")
            lines.append(f"  record_result \"{fix.vid}\" false \"failed\"")
            lines.append("  ((FAIL++))")
            lines.append("fi")
            lines.append("")

        lines.extend(
            [
                "echo \"Summary: PASS=$PASS FAIL=$FAIL SKIP=$SKIP\" | tee -a \"$LOG_FILE\"",
                "printf '{\\n  \"meta\": {\\n    \"generated\": \"%s\",\\n    \"mode\": \"%s\",\\n    \"total\": %d,\\n    \"pass\": %d,\\n    \"fail\": %d,\\n    \"skip\": %d\\n  },\\n  \"results\": [\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"$([ \"$DRY_RUN\" -eq 1 ] && echo 'dry' || echo 'live')\" $((PASS+FAIL+SKIP)) $PASS $FAIL $SKIP > \"$RESULT_FILE\"",
                "for i in \"${!RESULTS[@]}\"; do",
                "  printf '    %s%s\\n' \"${RESULTS[$i]}\" $([ \"$i\" -lt $(( ${#RESULTS[@]} - 1 )) ] && echo ',' ) >> \"$RESULT_FILE\"",
                "done",
                "printf '  ]\\n}\\n' >> \"$RESULT_FILE\"",
                "echo \"Results saved to $RESULT_FILE\" | tee -a \"$LOG_FILE\"",
            ]
        )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        if not Cfg.IS_WIN:
            with suppress(Exception):
                os.chmod(path, 0o750)

        LOG.i(f"Bash remediation script generated: {path} ({len(fixes)} fixes)")

    def to_powershell(self, path: Union[str, Path], severity_filter: Optional[List[str]] = None, dry_run: bool = False) -> None:
        path = San.path(path, mkpar=True)
        fixes = [
            fix
            for fix in self.fixes
            if fix.fix_command and fix.platform in ("windows", "generic") and (not severity_filter or fix.severity in severity_filter)
        ]
        if not fixes:
            LOG.w("No Windows/generic fixes with commands found")
            return

        lines: List[str] = [
            "#requires -RunAsAdministrator",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Mode: {'DRY RUN' if dry_run else 'LIVE'}",
            "",
            "$ErrorActionPreference = 'Stop'",
            f"$DryRun = {'$true' if dry_run else '$false'}",
            "$Log = \"stig_fix_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\"",
            "$Results = @()",
            "Start-Transcript -Path $Log -Append | Out-Null",
            "",
            "function Add-Result([string]$Vid, [bool]$Success, [string]$Message) {",
            "    $Results += [pscustomobject]@{",
            "        vid = $Vid;",
            "        ok = $Success;",
            "        msg = $Message;",
            "        ts = [DateTime]::UtcNow.ToString('o')",
            "    }",
            "}",
            "",
        ]

        for idx, fix in enumerate(fixes, 1):
            lines.append(f"Write-Host \"[{idx}/{len(fixes)}] {fix.vid} - {fix.title[:60]}\"")
            if dry_run:
                lines.append(f"Write-Host \"  [DRY-RUN] Would execute:`n{fix.fix_command}\"")
                lines.append(f"Add-Result \"{fix.vid}\" $true \"dry_run\"")
                lines.append("Continue")
                lines.append("")
                continue

            lines.append("try {")
            for line in fix.fix_command.splitlines():
                lines.append(f"    {line}")
            lines.append(f"    Write-Host \"  ✔ Success\"")
            lines.append(f"    Add-Result \"{fix.vid}\" $true \"success\"")
            lines.append("} catch {")
            lines.append("    Write-Warning \"  ✘ Failed: $($_.Exception.Message)\"")
            lines.append(f"    Add-Result \"{fix.vid}\" $false $_.Exception.Message")
            lines.append("}")
            lines.append("")

        lines.extend(
            [
                "Stop-Transcript | Out-Null",
                "[pscustomobject]@{",
                "    meta = @{",
                "        generated = [DateTime]::UtcNow.ToString('o');",
                "        mode = if ($DryRun) { 'dry' } else { 'live' };",
                "        total = $Results.Count;",
                "        pass = ($Results | Where-Object { $_.ok }).Count;",
                "        fail = ($Results | Where-Object { -not $_.ok }).Count;",
                "    };",
                "    results = $Results",
                "} | ConvertTo-Json -Depth 10 | Out-File \"stig_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json\" -Encoding utf8",
            ]
        )

        with FO.atomic(path) as handle:
            handle.write("\n".join(lines))

        LOG.i(f"PowerShell remediation script generated: {path} ({len(fixes)} fixes)")

    def stats_summary(self) -> Dict[str, Any]:
        return {
            "total_groups": self.stats["total_groups"],
            "with_fix": self.stats["with_fix"],
            "with_command": self.stats["with_command"],
            "platforms": dict(self.stats["platforms"]),
        }


# ──────────────────────────────────────────────────────────────────────────────
# FIX RESULTS (Bulk remediation import)
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class FixResult:
    vid: str
    ts: datetime
    ok: bool
    message: str = ""
    output: str = ""
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "vid": self.vid,
            "ts": self.ts.isoformat(),
            "ok": self.ok,
            "msg": self.message,
            "out": self.output,
            "err": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FixResult":
        if not isinstance(data, dict):
            raise ValidationError("Result entry must be object")
        vid = San.vuln(data.get("vid", ""))
        ts = datetime.now(timezone.utc)
        ts_str = data.get("ts")
        if ts_str:
            with suppress(Exception):
                ts = datetime.fromisoformat(ts_str.rstrip("Z"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return cls(
            vid=vid,
            ts=ts,
            ok=bool(data.get("ok", False)),
            message=str(data.get("msg", "") or ""),
            output=str(data.get("out", "") or ""),
            error=str(data.get("err", "") or ""),
        )


class FixResPro:
    """Bulk fix result processor."""

    def __init__(self):
        self.results: Dict[str, FixResult] = {}
        self.meta: Dict[str, Any] = {}

    # ------------------------------------------------------------------ import
    def load(self, path: Union[str, Path]) -> Tuple[int, int]:
        """
        Load remediation results from JSON with support for multiple formats.

        Supported formats:
        1. Array: [{"vid": "V-1", "ok": true, ...}, ...]
        2. Object: {"results": [...], "meta": {...}}
        3. Multi-system: {"systems": {"host1": [...], "host2": [...]}}
        4. Alternative keys: {"vulnerabilities": [...], "entries": [...]}

        Returns: (unique_count, skipped_count)
        """
        path = San.path(path, exist=True, file=True)
        LOG.ctx(op="load_fix_results", file=path.name)
        LOG.i("Loading remediation results JSON")

        try:
            content = FO.read(path)
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON in {path.name}: {exc}") from exc
        except Exception as exc:
            raise ParseError(f"Cannot read {path.name}: {exc}") from exc

        imported = 0
        skipped = 0
        entries = []

        # ═══ FORMAT DETECTION ═══
        if isinstance(payload, list):
            # Format 1: Direct array
            LOG.d("Detected array format")
            self.meta = {"format": "array", "source": str(path)}
            entries = payload

        elif isinstance(payload, dict):
            self.meta = payload.get("meta", {})
            self.meta["source"] = str(path)

            # Format 2: Standard "results" key
            if "results" in payload:
                LOG.d("Detected standard object format with 'results' key")
                entries = payload["results"]

            # Format 3: Multi-system grouped format
            elif "systems" in payload:
                LOG.i("Detected multi-system format")
                systems_data = payload["systems"]
                if isinstance(systems_data, dict):
                    for system_name, system_results in systems_data.items():
                        if isinstance(system_results, list):
                            # Tag each result with source system
                            for entry in system_results:
                                if isinstance(entry, dict):
                                    entry['_source_system'] = system_name
                            entries.extend(system_results)
                            LOG.d(f"  Loaded {len(system_results)} from system '{system_name}'")

            # Format 4: Alternative keys
            elif "vulnerabilities" in payload:
                LOG.d("Detected 'vulnerabilities' format")
                entries = payload["vulnerabilities"]
            elif "entries" in payload:
                LOG.d("Detected 'entries' format")
                entries = payload["entries"]
            elif "res" in payload:
                LOG.d("Detected 'res' format")
                entries = payload["res"]
            elif "findings" in payload:
                LOG.d("Detected 'findings' format")
                entries = payload["findings"]
            else:
                # Maybe the payload itself is a single result entry?
                if "vid" in payload:
                    LOG.d("Detected single result object")
                    entries = [payload]
                else:
                    raise ParseError(
                        f"Unrecognized JSON format. Expected keys: 'results', 'systems', "
                        f"'vulnerabilities', 'entries', or direct array. Found: {list(payload.keys())}"
                    )
        else:
            raise ParseError(f"JSON must be object or array, got {type(payload).__name__}")

        if not isinstance(entries, list):
            raise ParseError(f"Results must be array, got {type(entries).__name__}")

        if not entries:
            LOG.w("No entries found in results file")
            return 0, 0

        # ═══ PROCESS ENTRIES WITH DEDUPLICATION ═══
        dedup: Dict[str, FixResult] = {}

        for idx, entry in enumerate(entries, 1):
            try:
                result = FixResult.from_dict(entry)

                # Deduplication: keep most recent for each VID
                if result.vid in dedup:
                    existing = dedup[result.vid]
                    if result.ts > existing.ts:
                        LOG.d(f"  {result.vid}: replacing older result")
                        dedup[result.vid] = result
                    else:
                        LOG.d(f"  {result.vid}: keeping existing (newer)")
                else:
                    dedup[result.vid] = result

                imported += 1

            except Exception as exc:
                skipped += 1
                LOG.w(f"Entry {idx}: invalid - {exc}")
                continue

        # Merge with existing results (for multi-file batch)
        for vid, result in dedup.items():
            if vid in self.results:
                # Keep newer result
                if result.ts > self.results[vid].ts:
                    self.results[vid] = result
            else:
                self.results[vid] = result

        unique_count = len(dedup)
        LOG.i(f"Loaded {unique_count} unique results from {imported} total entries (skipped {skipped})")
        LOG.clear()

        return unique_count, skipped



    # ---------------------------------------------------------------- update ckl
    def update_ckl(
        self,
        checklist: Union[str, Path],
        out: Union[str, Path],
        *,
        auto_status: bool = True,
        dry: bool = False,
    ) -> Dict[str, Any]:
        checklist = San.path(checklist, exist=True, file=True)
        out = San.path(out, mkpar=True)

        LOG.ctx(op="apply_results", file=checklist.name)
        LOG.i(f"Applying remediation results to checklist ({len(self.results)} vulns)")

        try:
            tree = FO.parse_xml(checklist)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Unable to parse checklist: {exc}") from exc

        stigs = root.find("STIGS")
        if stigs is None:
            raise ParseError("Checklist missing STIGS section")

        updated = 0
        not_found: List[str] = []

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = self._get_vid(vuln)
                if not vid or vid not in self.results:
                    continue

                result = self.results[vid]
                updated += 1

                finding_node = vuln.find("FINDING_DETAILS")
                if finding_node is None:
                    finding_node = ET.SubElement(vuln, "FINDING_DETAILS")

                summary = [
                    "┌" + "─" * 78 + "┐",
                    "│ AUTOMATED REMEDIATION".center(80) + "│",
                    "└" + "─" * 78 + "┘",
                    f"Timestamp: {result.ts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    f"Result: {'✔ SUCCESS' if result.ok else '✘ FAILED'}",
                    f"Mode: {self.meta.get('mode', 'unknown')}",
                ]
                if result.message:
                    summary.append(f"Message: {result.message}")
                if result.output:
                    summary.append("")
                    summary.append("Output:")
                    summary.append(result.output)
                if result.error:
                    summary.append("")
                    summary.append("Error:")
                    summary.append(result.error)

                existing = finding_node.text or ""
                if existing.strip():
                    combined = "\n".join(summary) + "\n\n" + "═" * 80 + "\n[PREVIOUS]\n" + "═" * 80 + "\n\n" + existing
                else:
                    combined = "\n".join(summary)
                if len(combined) > Cfg.MAX_FIND:
                    combined = combined[: Cfg.MAX_FIND - 15] + "\n[TRUNCATED]"
                finding_node.text = combined

                comment_node = vuln.find("COMMENTS")
                if comment_node is None:
                    comment_node = ET.SubElement(vuln, "COMMENTS")
                comments = comment_node.text or ""
                entry = f"[Automated Remediation {result.ts.strftime('%Y-%m-%d %H:%M:%S UTC')}] {result.message or 'Refer to details'}"
                if comments.strip():
                    comment_node.text = entry + "\n" + comments
                else:
                    comment_node.text = entry

                if auto_status and result.ok:
                    status_node = vuln.find("STATUS")
                    if status_node is None:
                        status_node = ET.SubElement(vuln, "STATUS")
                    status_node.text = San.status("NotAFinding")

        # Track results that didn't match any vulnerability
        for vid in self.results:
            if not self._find_vuln(root, vid):
                not_found.append(vid)

        self._indent_xml(root)

        if dry:
            LOG.i("Dry-run requested, checklist not written")
            LOG.clear()
            return {
                "updated": updated,
                "not_found": not_found,
                "dry_run": True,
            }

        self._write_ckl(root, out)
        LOG.i(f"Checklist updated and saved to {out}")
        LOG.clear()

        return {
            "updated": updated,
            "not_found": not_found,
            "dry_run": False,
            "output": str(out),
        }

    # ---------------------------------------------------------------- helpers
    def _get_vid(self, vuln) -> Optional[str]:
        for sd in vuln.findall("STIG_DATA"):
            attr = sd.findtext("VULN_ATTRIBUTE")
            if attr == "Vuln_Num":
                value = sd.findtext("ATTRIBUTE_DATA")
                if value:
                    with suppress(Exception):
                        return San.vuln(value.strip())
        return None

    def _find_vuln(self, root, vid: str) -> bool:
        for sd in root.findall(".//STIG_DATA"):
            attr = sd.findtext("VULN_ATTRIBUTE")
            if attr == "Vuln_Num":
                value = sd.findtext("ATTRIBUTE_DATA")
                if value and value.strip() == vid:
                    return True
        return False

    def _indent_xml(self, elem, level: int = 0) -> None:
        indent = "\n" + "\t" * level
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = indent + "\t"
            for i, child in enumerate(elem):
                self._indent_xml(child, level + 1)
                if not child.tail or not child.tail.strip():
                    # Last child gets dedented, others get full indent
                    child.tail = indent if i == len(elem) - 1 else indent + "\t"
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = indent

    def _write_ckl(self, root, out: Path) -> None:
        with FO.atomic(out, mode="wb", bak=False) as handle:
            handle.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            handle.write(f"<!--{Sch.COMMENT}-->\n".encode("utf-8"))
            xml_text = ET.tostring(root, encoding="unicode", method="xml")
            handle.write(xml_text.encode("utf-8"))


# ──────────────────────────────────────────────────────────────────────────────
# EVIDENCE MANAGER
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class EvidenceMeta:
    vid: str
    filename: str
    imported: datetime
    file_hash: str
    file_size: int
    description: str = ""
    category: str = "general"
    who: str = "System"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "vid": self.vid,
            "filename": self.filename,
            "imported": self.imported.isoformat(),
            "hash": self.file_hash,
            "size": self.file_size,
            "description": self.description,
            "category": self.category,
            "who": self.who,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceMeta":
        if not isinstance(data, dict):
            raise ValidationError("Evidence metadata must be object")
        vid = San.vuln(data.get("vid", ""))
        imported = datetime.now(timezone.utc)
        imported_str = data.get("imported")
        if imported_str:
            with suppress(Exception):
                imported = datetime.fromisoformat(imported_str.rstrip("Z"))
        if imported.tzinfo is None:
            imported = imported.replace(tzinfo=timezone.utc)
        return cls(
            vid=vid,
            filename=str(data.get("filename", "")),
            imported=imported,
            file_hash=str(data.get("hash", "")),
            file_size=int(data.get("size", 0)),
            description=str(data.get("description", "")),
            category=str(data.get("category", "general")),
            who=str(data.get("who", "System")),
        )


class EvidenceMgr:
    """Evidence file manager."""

    def __init__(self):
        self.base = Cfg.EVIDENCE_DIR
        self.meta_file = self.base / "meta.json"
        self._meta: Dict[str, List[EvidenceMeta]] = defaultdict(list)
        self._lock = threading.RLock()
        self._load()

    # ------------------------------------------------------------------- load
    def _load(self) -> None:
        if not self.meta_file.exists():
            return
        with suppress(Exception):
            data = json.loads(FO.read(self.meta_file))
            for vid, entries in data.items():
                try:
                    vid = San.vuln(vid)
                except Exception:
                    continue
                self._meta[vid] = []
                for entry in entries:
                    with suppress(Exception):
                        meta = EvidenceMeta.from_dict(entry)
                        self._meta[vid].append(meta)

    # ------------------------------------------------------------------- save
    def _save(self) -> None:
        payload = {vid: [entry.as_dict() for entry in entries] for vid, entries in self._meta.items()}
        with FO.atomic(self.meta_file) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------- import
    def import_file(
        self,
        vid: str,
        file_path: Union[str, Path],
        *,
        description: str = "",
        category: str = "general",
    ) -> Path:
        vid = San.vuln(vid)
        file_path = San.path(file_path, exist=True, file=True)

        LOG.ctx(op="import_evidence", vid=vid)
        LOG.i(f"Importing evidence for {vid}: {file_path}")

        dest_dir = self.base / vid
        dest_dir.mkdir(parents=True, exist_ok=True)

        file_hash = hashlib.sha256()
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                file_hash.update(chunk)

        digest = file_hash.hexdigest()
        file_size = file_path.stat().st_size

        with self._lock:
            for entry in self._meta[vid]:
                if entry.file_hash == digest:
                    LOG.w("Duplicate evidence detected, returning existing path")
                    return dest_dir / entry.filename

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r"[^\w.-]", "_", file_path.name)
            dest_name = f"{timestamp}_{safe_name}"
            dest = dest_dir / dest_name
            shutil.copy2(file_path, dest)

            meta = EvidenceMeta(
                vid=vid,
                filename=dest_name,
                imported=datetime.now(timezone.utc),
                file_hash=digest,
                file_size=file_size,
                description=description,
                category=category,
                who=os.getenv("USER") or os.getenv("USERNAME") or "System",
            )
            self._meta[vid].append(meta)
            self._save()

        LOG.i(f"Evidence imported to {dest}")
        LOG.clear()
        return dest

    # ------------------------------------------------------------------- export
    def export_all(self, dest_dir: Union[str, Path]) -> int:
        dest_dir = San.path(dest_dir, mkpar=True, dir=True)
        LOG.ctx(op="export_evidence")
        LOG.i(f"Exporting evidence to {dest_dir}")

        copied = 0
        with self._lock:
            for vid, entries in self._meta.items():
                source_dir = self.base / vid
                if not source_dir.exists():
                    continue
                target_vid_dir = dest_dir / vid
                target_vid_dir.mkdir(parents=True, exist_ok=True)
                for entry in entries:
                    source_file = source_dir / entry.filename
                    if not source_file.exists():
                        continue
                    shutil.copy2(source_file, target_vid_dir / entry.filename)
                    copied += 1

        metadata_path = dest_dir / "evidence_meta.json"
        with FO.atomic(metadata_path) as handle:
            json.dump(
                {vid: [entry.as_dict() for entry in entries] for vid, entries in self._meta.items()},
                handle,
                indent=2,
                ensure_ascii=False,
            )

        LOG.i(f"Exported {copied} evidence files")
        LOG.clear()
        return copied

    # ------------------------------------------------------------------- package
    def package(self, zip_path: Union[str, Path]) -> Path:
        zip_path = San.path(zip_path, mkpar=True)
        LOG.ctx(op="package_evidence")
        LOG.i(f"Packaging evidence into {zip_path}")

        files: Dict[str, Path] = {}
        with self._lock:
            for vid, entries in self._meta.items():
                for entry in entries:
                    source = self.base / vid / entry.filename
                    if source.exists():
                        files[f"{vid}/{entry.filename}"] = source

        tmp_meta = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        meta_path = Path(tmp_meta.name)
        with tmp_meta:
            json.dump(
                {vid: [entry.as_dict() for entry in entries] for vid, entries in self._meta.items()},
                tmp_meta,
                indent=2,
                ensure_ascii=False,
            )

        files["meta.json"] = meta_path

        try:
            archive = FO.zip(zip_path, files, base="evidence")
        finally:
            with suppress(Exception):
                meta_path.unlink()

        LOG.i(f"Evidence package created: {archive}")
        LOG.clear()
        return archive

    # ------------------------------------------------------------------- import pkg
    def import_package(self, package: Union[str, Path]) -> int:
        package = San.path(package, exist=True, file=True)
        LOG.ctx(op="import_evidence_package", file=package.name)
        LOG.i("Importing evidence package")

        extracted = 0
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with zipfile.ZipFile(package, "r") as archive:
                archive.extractall(tmp_path)

            evidence_dir = tmp_path / "evidence"
            if evidence_dir.exists():
                meta_file = evidence_dir / "meta.json"
            else:
                evidence_dir = tmp_path
                meta_file = tmp_path / "meta.json"

            if meta_file.exists():
                meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
            else:
                meta_data = {}

            for vid_dir in evidence_dir.iterdir():
                if not vid_dir.is_dir():
                    continue
                vid = vid_dir.name
                try:
                    vid = San.vuln(vid)
                except Exception:
                    continue
                for file in vid_dir.iterdir():
                    if not file.is_file():
                        continue
                    description = ""
                    category = "general"
                    for entry in meta_data.get(vid, []):
                        if entry.get("filename") == file.name:
                            description = entry.get("description", "")
                            category = entry.get("category", "general")
                            break
                    self.import_file(vid, file, description=description, category=category)
                    extracted += 1

        LOG.i(f"Imported {extracted} evidence files from package")
        LOG.clear()
        return extracted

    # ------------------------------------------------------------------- summary
    def summary(self) -> Dict[str, Any]:
        with self._lock:
            total_files = sum(len(entries) for entries in self._meta.values())
            total_size = sum(entry.file_size for entries in self._meta.values() for entry in entries)
            return {
                "vulnerabilities": len(self._meta),
                "files": total_files,
                "size_bytes": total_size,
                "size_mb": total_size / (1024 * 1024),
                "storage": str(self.base),
            }


# ──────────────────────────────────────────────────────────────────────────────
# PRESET MANAGER
# ──────────────────────────────────────────────────────────────────────────────


class PresetMgr:
    """CLI/GUI presets."""

    def __init__(self):
        self.base = Cfg.PRESET_DIR
        self.presets: Dict[str, Dict[str, Any]] = {}
        self._load_all()

    def _load_all(self) -> None:
        if not self.base.exists():
            return
        for file in self.base.glob("*.json"):
            with suppress(Exception):
                data = json.loads(FO.read(file))
                if isinstance(data, dict):
                    self.presets[file.stem] = data

    def save(self, name: str, payload: Dict[str, Any]) -> None:
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", name).strip("_")
        if not name:
            raise ValidationError("Invalid preset name")
        path = self.base / f"{name}.json"
        payload = dict(payload)
        payload["_version"] = VERSION
        payload["_saved_at"] = datetime.now(timezone.utc).isoformat()
        with FO.atomic(path) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        self.presets[name] = payload
        LOG.i(f"Preset saved: {name}")

    def load(self, name: str) -> Optional[Dict[str, Any]]:
        return self.presets.get(name)

    def list(self) -> List[str]:
        return sorted(self.presets.keys())

    def delete(self, name: str) -> bool:
        if name not in self.presets:
            return False
        path = self.base / f"{name}.json"
        with suppress(Exception):
            path.unlink()
        del self.presets[name]
        LOG.i(f"Preset deleted: {name}")
        return True


# ──────────────────────────────────────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────────────────────────────────────

if Deps.HAS_TKINTER:

    class GUI:
        """Graphical interface."""

        def __init__(self):
            self.root = tk.Tk()
            self.root.title(f"{APP_NAME} v{VERSION}")
            self.root.geometry("1100x760")
            with suppress(Exception):
                self.root.iconbitmap(False)

            self.proc = Proc()
            self.evidence = EvidenceMgr()
            self.presets = PresetMgr()
            self.queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

            self._build_menus()
            self._build_tabs()
            self.root.protocol("WM_DELETE_WINDOW", self._close)
            self.root.after(200, self._process_queue)

        # --------------------------------------------------------------- UI setup
        def _build_menus(self) -> None:
            menu = tk.Menu(self.root)
            self.root.config(menu=menu)

            file_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="File", menu=file_menu)
            file_menu.add_command(label="Save Preset…", command=self._save_preset)
            file_menu.add_command(label="Load Preset…", command=self._load_preset)
            file_menu.add_separator()
            file_menu.add_command(label="Exit", command=self._close)

            tools_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="Tools", menu=tools_menu)
            tools_menu.add_command(label="Export History…", command=self._export_history)
            tools_menu.add_command(label="Import History…", command=self._import_history)
            tools_menu.add_separator()
            tools_menu.add_command(label="Export Boilerplates…", command=self._export_boiler)
            tools_menu.add_command(label="Import Boilerplates…", command=self._import_boiler)
            tools_menu.add_separator()
            tools_menu.add_command(label="Cleanup Old Files", command=self._cleanup_old)

            help_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="About", command=self._about)

        def _build_tabs(self) -> None:
            notebook = ttk.Notebook(self.root)
            notebook.pack(fill="both", expand=True, padx=5, pady=5)

            tabs = [
                ("Create CKL", self._tab_create),
                ("Merge Checklists", self._tab_merge),
                ("Extract Fixes", self._tab_extract),
                ("Import Results", self._tab_results),
                ("Evidence", self._tab_evidence),
                ("Validate", self._tab_validate),
            ]

            for title, builder in tabs:
                frame = ttk.Frame(notebook, padding=10)
                notebook.add(frame, text=title)
                builder(frame)

        # --------------------------------------------------------------- tabs
        def _tab_create(self, frame):
            r = 0
            ttk.Label(frame, text="XCCDF File:").grid(row=r, column=0, sticky="w")
            self.create_xccdf = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_xccdf, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_create_xccdf).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Asset Name: *").grid(row=r, column=0, sticky="w")
            self.create_asset = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_asset, width=70).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="IP Address:").grid(row=r, column=0, sticky="w")
            self.create_ip = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_ip, width=70).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="MAC Address:").grid(row=r, column=0, sticky="w")
            self.create_mac = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_mac, width=70).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="Marking:").grid(row=r, column=0, sticky="w")
            self.create_mark = tk.StringVar(value="CUI")
            ttk.Combobox(
                frame,
                textvariable=self.create_mark,
                values=sorted(Sch.MARKS),
                width=67,
                state="readonly",
            ).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="Output CKL:").grid(row=r, column=0, sticky="w")
            self.create_out = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_out, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_create_out).grid(row=r, column=2)
            r += 1

            self.create_bp = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                frame,
                text="Apply boilerplate templates",
                variable=self.create_bp,
            ).grid(row=r, column=1, sticky="w")
            r += 1

            ttk.Button(
                frame,
                text="Create Checklist",
                command=self._do_create,
                width=25,
            ).grid(row=r, column=1, pady=15)
            r += 1

            self.create_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.create_status, wraplength=860, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )

        def _tab_merge(self, frame):
            r = 0
            ttk.Label(frame, text="Base Checklist:").grid(row=r, column=0, sticky="w")
            self.merge_base = tk.StringVar()
            ttk.Entry(frame, textvariable=self.merge_base, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_merge_base).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Historical Files:").grid(row=r, column=0, sticky="nw")
            list_frame = ttk.Frame(frame)
            list_frame.grid(row=r, column=1, padx=5, sticky="ew")
            self.merge_list = tk.Listbox(list_frame, height=6, width=60)
            self.merge_list.pack(side="left", fill="both", expand=True)
            scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.merge_list.yview)
            scrollbar.pack(side="right", fill="y")
            self.merge_list.config(yscrollcommand=scrollbar.set)

            btn_frame = ttk.Frame(frame)
            btn_frame.grid(row=r, column=2, sticky="n")
            ttk.Button(btn_frame, text="Add…", command=self._add_merge_hist).pack(fill="x", pady=2)
            ttk.Button(btn_frame, text="Remove", command=self._remove_merge_hist).pack(fill="x", pady=2)
            ttk.Button(btn_frame, text="Clear", command=self._clear_merge_hist).pack(fill="x", pady=2)
            self.merge_histories: List[str] = []
            r += 1

            ttk.Label(frame, text="Output CKL:").grid(row=r, column=0, sticky="w")
            self.merge_out = tk.StringVar()
            ttk.Entry(frame, textvariable=self.merge_out, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_merge_out).grid(row=r, column=2)
            r += 1

            options = ttk.LabelFrame(frame, text="Options", padding=10)
            options.grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
            self.merge_preserve = tk.BooleanVar(value=True)
            ttk.Checkbutton(options, text="Preserve full history", variable=self.merge_preserve).pack(anchor="w")
            self.merge_bp = tk.BooleanVar(value=True)
            ttk.Checkbutton(options, text="Apply boilerplates when missing", variable=self.merge_bp).pack(anchor="w")
            r += 1

            ttk.Button(frame, text="Merge Checklists", command=self._do_merge, width=25).grid(row=r, column=1, pady=15)
            r += 1

            self.merge_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.merge_status, wraplength=860, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )

        def _tab_extract(self, frame):
            r = 0
            ttk.Label(frame, text="XCCDF File:").grid(row=r, column=0, sticky="w")
            self.extract_xccdf = tk.StringVar()
            ttk.Entry(frame, textvariable=self.extract_xccdf, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_extract_xccdf).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Output Directory:").grid(row=r, column=0, sticky="w")
            self.extract_outdir = tk.StringVar()
            ttk.Entry(frame, textvariable=self.extract_outdir, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_extract_out).grid(row=r, column=2)
            r += 1

            formats = ttk.LabelFrame(frame, text="Export Formats", padding=10)
            formats.grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
            self.extract_json = tk.BooleanVar(value=True)
            self.extract_csv = tk.BooleanVar(value=True)
            self.extract_bash = tk.BooleanVar(value=True)
            self.extract_ps = tk.BooleanVar(value=True)
            ttk.Checkbutton(formats, text="JSON", variable=self.extract_json).grid(row=0, column=0, padx=10)
            ttk.Checkbutton(formats, text="CSV", variable=self.extract_csv).grid(row=0, column=1, padx=10)
            ttk.Checkbutton(formats, text="Bash", variable=self.extract_bash).grid(row=0, column=2, padx=10)
            ttk.Checkbutton(formats, text="PowerShell", variable=self.extract_ps).grid(row=0, column=3, padx=10)
            r += 1

            self.extract_dry = tk.BooleanVar(value=False)
            ttk.Checkbutton(frame, text="Generate scripts in dry-run mode", variable=self.extract_dry).grid(
                row=r, column=1, sticky="w"
            )
            r += 1

            ttk.Button(frame, text="Extract Fixes", command=self._do_extract, width=25).grid(row=r, column=1, pady=15)
            r += 1

            self.extract_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.extract_status, wraplength=860, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )

        def _tab_results(self, frame):
            """Results import tab with batch file support."""
            r = 0

            # ═══ BATCH IMPORT ═══
            batch_frame = ttk.LabelFrame(frame, text="📁 Batch Import (Multiple JSON Files)", padding=10)
            batch_frame.grid(row=r, column=0, columnspan=3, sticky="ew", pady=(0, 10))

            ttk.Label(batch_frame, text="Results Files:").grid(row=0, column=0, sticky="nw", padx=5, pady=5)

            list_container = ttk.Frame(batch_frame)
            list_container.grid(row=0, column=1, padx=5, sticky="ew")

            self.results_list = tk.Listbox(list_container, height=5, width=65, selectmode=tk.EXTENDED)
            self.results_list.pack(side="left", fill="both", expand=True)

            scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.results_list.yview)
            scrollbar.pack(side="right", fill="y")
            self.results_list.config(yscrollcommand=scrollbar.set)

            self.results_files: List[str] = []

            btn_container = ttk.Frame(batch_frame)
            btn_container.grid(row=0, column=2, sticky="n", padx=5)
            ttk.Button(btn_container, text="Add Files…", command=self._add_results_files, width=15).pack(fill="x", pady=2)
            ttk.Button(btn_container, text="Remove", command=self._remove_results_file, width=15).pack(fill="x", pady=2)
            ttk.Button(btn_container, text="Clear All", command=self._clear_results_files, width=15).pack(fill="x", pady=2)

            batch_frame.columnconfigure(1, weight=1)
            r += 1

            # ═══ SINGLE FILE (LEGACY) ═══
            single_frame = ttk.LabelFrame(frame, text="📄 Single File Import", padding=10)
            single_frame.grid(row=r, column=0, columnspan=3, sticky="ew", pady=(0, 10))

            ttk.Label(single_frame, text="Results JSON:").grid(row=0, column=0, sticky="w", padx=5)
            self.results_json = tk.StringVar()
            ttk.Entry(single_frame, textvariable=self.results_json, width=70).grid(row=0, column=1, padx=5)
            ttk.Button(single_frame, text="Browse…", command=self._browse_results_json).grid(row=0, column=2, padx=5)
            r += 1

            # ═══ TARGET CHECKLIST ═══
            ttk.Label(frame, text="Target Checklist (CKL):").grid(row=r, column=0, sticky="w")
            self.results_ckl = tk.StringVar()
            ttk.Entry(frame, textvariable=self.results_ckl, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_results_ckl).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Output CKL:").grid(row=r, column=0, sticky="w")
            self.results_out = tk.StringVar()
            ttk.Entry(frame, textvariable=self.results_out, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_results_out).grid(row=r, column=2)
            r += 1

            # ═══ OPTIONS ═══
            self.results_auto = tk.BooleanVar(value=True)
            ttk.Checkbutton(
                frame,
                text="Auto-mark successful remediations as NotAFinding",
                variable=self.results_auto,
            ).grid(row=r, column=1, sticky="w")
            r += 1

            self.results_dry = tk.BooleanVar(value=False)
            ttk.Checkbutton(frame, text="Dry run (preview only)", variable=self.results_dry).grid(
                row=r, column=1, sticky="w"
            )
            r += 1

            # ═══ ACTION ═══
            ttk.Button(frame, text="Apply Remediation Results", command=self._do_results, width=30).grid(row=r, column=1, pady=15)
            r += 1

            # ═══ STATUS ═══
            self.results_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.results_status, wraplength=900, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )


        # Add helper methods for batch file management:

        def _add_results_files(self):
            """Add multiple result files to batch queue."""
            paths = filedialog.askopenfilenames(
                title="Select Remediation Results (Ctrl+Click for multiple)",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
            )
            added = 0
            for path in paths:
                if path and path not in self.results_files:
                    self.results_files.append(path)
                    self.results_list.insert(tk.END, Path(path).name)
                    added += 1

            if added:
                self.results_status.set(f"✓ Added {added} file(s) - Total: {len(self.results_files)} queued")

        def _remove_results_file(self):
            """Remove selected files from batch queue."""
            selections = self.results_list.curselection()
            if not selections:
                return

            for index in reversed(selections):
                self.results_list.delete(index)
                self.results_files.pop(index)

            self.results_status.set(f"{len(self.results_files)} file(s) remaining")

        def _clear_results_files(self):
            """Clear all files from batch queue."""
            self.results_files.clear()
            self.results_list.delete(0, tk.END)
            self.results_status.set("Queue cleared")



        def _do_results(self):
            """Apply remediation results with batch import support."""
            if not self.results_ckl.get() or not self.results_out.get():
                messagebox.showerror("Missing input", "Please provide checklist and output path.")
                return

            # Collect files: batch list takes priority over single field
            files_to_process = []
            if self.results_files:
                files_to_process = list(self.results_files)
            elif self.results_json.get():
                files_to_process = [self.results_json.get()]
            else:
                messagebox.showerror("Missing input", "Please add result files or specify single JSON file.")
                return

            dry = self.results_dry.get()
            auto = self.results_auto.get()

            def work():
                """Background batch processor."""
                combined_processor = FixResPro()
                total_loaded = 0
                total_skipped = 0
                failed_files = []

                for idx, result_file in enumerate(files_to_process, 1):
                    try:
                        LOG.i(f"Loading {idx}/{len(files_to_process)}: {Path(result_file).name}")
                        imported, skipped = combined_processor.load(result_file)
                        total_loaded += imported
                        total_skipped += skipped
                    except Exception as exc:
                        LOG.e(f"Failed to load {result_file}: {exc}")
                        failed_files.append((Path(result_file).name, str(exc)))
                        continue

                if not combined_processor.results:
                    raise ValidationError("No valid results loaded from any file")

                result = combined_processor.update_ckl(
                    self.results_ckl.get(),
                    self.results_out.get(),
                    auto_status=auto,
                    dry=dry,
                )
                result['total_loaded'] = total_loaded
                result['total_skipped'] = total_skipped
                result['files_processed'] = len(files_to_process)
                result['failed_files'] = failed_files
                return result

            def done(result):
                """Completion handler."""
                if isinstance(result, Exception):
                    self.results_status.set(f"✘ Error: {result}")
                    messagebox.showerror("Import Failed", str(result))
                else:
                    nf = result.get("not_found", [])
                    nf_display = f"{len(nf)} VIDs" if nf else "None"

                    summary = (
                        f"✔ Batch import complete!\n"
                        f"Files: {result.get('files_processed', 0)} | "
                        f"Results loaded: {result.get('total_loaded', 0)} | "
                        f"Skipped: {result.get('total_skipped', 0)}\n"
                        f"Vulnerabilities updated: {result.get('updated', 0)} | "
                        f"Not found: {nf_display}\n"
                        f"Output: {result.get('output', 'dry run')}"
                    )

                    self.results_status.set(summary)
                    messagebox.showinfo("Success", summary)

            self.results_status.set("Processing batch import…")
            self._async(work, done)




        def _tab_evidence(self, frame):
            ttk.Label(frame, text="Evidence Manager", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")

            import_frame = ttk.LabelFrame(frame, text="Import Evidence", padding=10)
            import_frame.pack(fill="x", pady=10)
            ttk.Label(import_frame, text="Vuln ID:").grid(row=0, column=0, sticky="w")
            self.evid_vid = tk.StringVar()
            ttk.Entry(import_frame, textvariable=self.evid_vid, width=25).grid(row=0, column=1, padx=5)
            ttk.Label(import_frame, text="Description:").grid(row=0, column=2, sticky="w")
            self.evid_desc = tk.StringVar()
            ttk.Entry(import_frame, textvariable=self.evid_desc, width=30).grid(row=0, column=3, padx=5)
            ttk.Label(import_frame, text="Category:").grid(row=0, column=4, sticky="w")
            self.evid_cat = tk.StringVar(value="general")
            ttk.Entry(import_frame, textvariable=self.evid_cat, width=15).grid(row=0, column=5, padx=5)
            ttk.Button(import_frame, text="Select & Import…", command=self._import_evidence).grid(row=0, column=6, padx=5)

            action_frame = ttk.LabelFrame(frame, text="Export / Package", padding=10)
            action_frame.pack(fill="x", pady=10)
            ttk.Button(action_frame, text="Export All…", command=self._export_evidence).grid(row=0, column=0, padx=5, pady=5)
            ttk.Button(action_frame, text="Create Package…", command=self._package_evidence).grid(row=0, column=1, padx=5, pady=5)
            ttk.Button(action_frame, text="Import Package…", command=self._import_evidence_package).grid(
                row=0, column=2, padx=5, pady=5
            )

            summary_frame = ttk.LabelFrame(frame, text="Summary", padding=10)
            summary_frame.pack(fill="both", expand=True, pady=10)
            self.evid_summary = tk.StringVar()
            ttk.Label(summary_frame, textvariable=self.evid_summary, justify="left", font=("Courier New", 10)).pack(
                anchor="w", pady=5
            )
            self._refresh_evidence_summary()

        def _tab_validate(self, frame):
            ttk.Label(frame, text="Validate Checklist", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")

            input_frame = ttk.Frame(frame)
            input_frame.pack(fill="x", pady=10)
            ttk.Label(input_frame, text="Checklist (CKL):").pack(side="left")
            self.validate_ckl = tk.StringVar()
            ttk.Entry(input_frame, textvariable=self.validate_ckl, width=60).pack(side="left", padx=5)
            ttk.Button(input_frame, text="Browse…", command=self._browse_validate_ckl).pack(side="left", padx=5)
            ttk.Button(input_frame, text="Validate", command=self._do_validate).pack(side="left")

            self.validate_text = ScrolledText(frame, width=120, height=25, font=("Courier New", 10))
            self.validate_text.pack(fill="both", expand=True, pady=5)

        # --------------------------------------------------------- action helpers
        def _async(self, work_func, callback):
            def worker():
                try:
                    result = work_func()
                except Exception as exc:
                    result = exc
                self.queue.put(("callback", callback, result))

            threading.Thread(target=worker, daemon=True).start()

        def _process_queue(self):
            """Process async callback queue with status update support."""
            try:
                while True:
                    item = self.queue.get_nowait()

                    # Handle different message types
                    if len(item) == 3:
                        # Standard callback format
                        kind, func, payload = item
                        if kind == "callback":
                            func(payload)
                    elif len(item) == 2:
                        # Status update format
                        kind, message = item
                        if kind == "status":
                            self.results_status.set(message)
                            self.root.update_idletasks()  # Force UI refresh
            except queue.Empty:
                pass

            self.root.after(200, self._process_queue)


        # -------------------------------------------------------------- browse
        def _browse_create_xccdf(self):
            path = filedialog.askopenfilename(title="Select XCCDF", filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")])
            if path:
                self.create_xccdf.set(path)
                if not self.create_out.get():
                    self.create_out.set(str(Path(path).with_suffix(".ckl")))

        def _browse_create_out(self):
            path = filedialog.asksaveasfilename(
                title="Save CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl"), ("All Files", "*.*")],
            )
            if path:
                self.create_out.set(path)

        def _browse_merge_base(self):
            path = filedialog.askopenfilename(title="Select base CKL", filetypes=[("CKL Files", "*.ckl")])
            if path:
                self.merge_base.set(path)

        def _browse_merge_out(self):
            path = filedialog.asksaveasfilename(
                title="Save merged CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.merge_out.set(path)

        def _browse_extract_xccdf(self):
            path = filedialog.askopenfilename(title="Select XCCDF", filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")])
            if path:
                self.extract_xccdf.set(path)

        def _browse_extract_out(self):
            path = filedialog.askdirectory(title="Select output directory")
            if path:
                self.extract_outdir.set(path)

        def _browse_results_json(self):
            path = filedialog.askopenfilename(title="Select results JSON", filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
            if path:
                self.results_json.set(path)

        def _browse_results_ckl(self):
            path = filedialog.askopenfilename(title="Select checklist", filetypes=[("CKL Files", "*.ckl")])
            if path:
                self.results_ckl.set(path)
                if not self.results_out.get():
                    out_path = Path(path).with_name(Path(path).stem + "_updated.ckl")
                    self.results_out.set(str(out_path))

        def _browse_results_out(self):
            path = filedialog.asksaveasfilename(
                title="Save updated CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.results_out.set(path)

        def _browse_validate_ckl(self):
            path = filedialog.askopenfilename(title="Select CKL", filetypes=[("CKL Files", "*.ckl")])
            if path:
                self.validate_ckl.set(path)

        # ------------------------------------------------------------ actions
        def _do_create(self):
            if not self.create_xccdf.get() or not self.create_asset.get() or not self.create_out.get():
                messagebox.showerror("Missing input", "Please provide XCCDF, asset name, and output path.")
                return

            def work():
                return self.proc.xccdf_to_ckl(
                    self.create_xccdf.get(),
                    self.create_out.get(),
                    self.create_asset.get(),
                    ip=self.create_ip.get(),
                    mac=self.create_mac.get(),
                    marking=self.create_mark.get(),
                    apply_boilerplate=self.create_bp.get(),
                )

            def done(result):
                if isinstance(result, Exception):
                    self.create_status.set(f"✘ Error: {result}")
                else:
                    self.create_status.set(
                        f"✔ Checklist created: {result.get('output')}\n"
                        f"Processed: {result.get('processed')} | Skipped: {result.get('skipped')}"
                    )

            self.create_status.set("Processing…")
            self._async(work, done)

        def _add_merge_hist(self):
            paths = filedialog.askopenfilenames(title="Select historical CKL", filetypes=[("CKL Files", "*.ckl")])
            for path in paths:
                if path not in self.merge_histories:
                    self.merge_histories.append(path)
                    self.merge_list.insert(tk.END, path)

        def _remove_merge_hist(self):
            selection = self.merge_list.curselection()
            if not selection:
                return
            index = selection[0]
            path = self.merge_histories.pop(index)
            self.merge_list.delete(index)
            LOG.d(f"Removed historical checklist: {path}")

        def _clear_merge_hist(self):
            self.merge_histories.clear()
            self.merge_list.delete(0, tk.END)

        def _do_merge(self):
            if not self.merge_base.get() or not self.merge_out.get():
                messagebox.showerror("Missing input", "Please provide base checklist and output path.")
                return

            histories = list(self.merge_histories)

            def work():
                return self.proc.merge(
                    self.merge_base.get(),
                    histories,
                    self.merge_out.get(),
                    preserve_history=self.merge_preserve.get(),
                    apply_boilerplate=self.merge_bp.get(),
                )

            def done(result):
                if isinstance(result, Exception):
                    self.merge_status.set(f"✘ Error: {result}")
                else:
                    self.merge_status.set(
                        f"✔ Merged checklist: {result.get('output')}\n"
                        f"Updated: {result.get('updated')} | Skipped: {result.get('skipped')}"
                    )

            self.merge_status.set("Processing…")
            self._async(work, done)

        def _do_extract(self):
            if not self.extract_xccdf.get() or not self.extract_outdir.get():
                messagebox.showerror("Missing input", "Please provide XCCDF file and output directory.")
                return

            outdir = Path(self.extract_outdir.get())
            outdir.mkdir(parents=True, exist_ok=True)

            def work():
                extractor = FixExt(self.extract_xccdf.get())
                fixes = extractor.extract()
                outpaths = []
                if self.extract_json.get():
                    extractor.to_json(outdir / "fixes.json")
                    outpaths.append("JSON")
                if self.extract_csv.get():
                    extractor.to_csv(outdir / "fixes.csv")
                    outpaths.append("CSV")
                if self.extract_bash.get():
                    extractor.to_bash(outdir / "remediate.sh", dry_run=self.extract_dry.get())
                    outpaths.append("Bash")
                if self.extract_ps.get():
                    extractor.to_powershell(outdir / "Remediate.ps1", dry_run=self.extract_dry.get())
                    outpaths.append("PowerShell")
                return extractor.stats_summary(), outpaths

            def done(result):
                if isinstance(result, Exception):
                    self.extract_status.set(f"✘ Error: {result}")
                else:
                    stats, formats = result
                    self.extract_status.set(
                        f"✔ Fix extraction complete\n"
                        f"Total groups: {stats['total_groups']} | With fixes: {stats['with_fix']} | "
                        f"Commands: {stats['with_command']}\n"
                        f"Formats: {', '.join(formats)}"
                    )

            self.extract_status.set("Processing…")
            self._async(work, done)

        def _import_evidence(self):
            vid = self.evid_vid.get()
            if not vid:
                messagebox.showerror("Missing input", "Please enter a vulnerability ID.")
                return
            try:
                San.vuln(vid)
            except Exception:
                messagebox.showerror("Invalid Vuln ID", "Please enter a valid Vuln ID (e.g. V-12345).")
                return
            path = filedialog.askopenfilename(title="Select evidence file")
            if not path:
                return

            def work():
                return self.evidence.import_file(
                    vid,
                    path,
                    description=self.evid_desc.get(),
                    category=self.evid_cat.get() or "general",
                )

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Error importing evidence", str(result))
                else:
                    messagebox.showinfo("Evidence Imported", f"Evidence stored at:\n{result}")
                    self._refresh_evidence_summary()
                    self.evid_vid.set("")
                    self.evid_desc.set("")
                    self.evid_cat.set("general")

            self._async(work, done)

        def _export_evidence(self):
            path = filedialog.askdirectory(title="Select export directory")
            if not path:
                return

            def work():
                return self.evidence.export_all(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Export error", str(result))
                else:
                    messagebox.showinfo("Evidence Export", f"Exported {result} file(s) to {path}")

            self._async(work, done)

        def _package_evidence(self):
            path = filedialog.asksaveasfilename(
                title="Save evidence package",
                defaultextension=".zip",
                filetypes=[("ZIP Files", "*.zip")],
            )
            if not path:
                return

            def work():
                return self.evidence.package(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Package error", str(result))
                else:
                    messagebox.showinfo("Evidence Package", f"Package created:\n{result}")

            self._async(work, done)

        def _import_evidence_package(self):
            path = filedialog.askopenfilename(title="Select evidence package", filetypes=[("ZIP Files", "*.zip")])
            if not path:
                return

            def work():
                return self.evidence.import_package(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Import error", str(result))
                else:
                    messagebox.showinfo("Evidence import", f"Imported {result} file(s)")
                    self._refresh_evidence_summary()

            self._async(work, done)

        def _do_validate(self):
            if not self.validate_ckl.get():
                messagebox.showerror("Missing input", "Please select a CKL file.")
                return

            def work():
                return self.proc.validator.validate(self.validate_ckl.get())

            def done(result):
                if isinstance(result, Exception):
                    self.validate_text.insert("end", f"✘ Error: {result}\n")
                    return
                ok, errors, warnings_, info = result
                self.validate_text.delete("1.0", "end")
                self.validate_text.insert("end", "=" * 80 + "\n")
                self.validate_text.insert("end", f"Validation Report - {datetime.now()}\n")
                self.validate_text.insert("end", "=" * 80 + "\n\n")
                if errors:
                    self.validate_text.insert("end", "Errors:\n", "error")
                    for err in errors:
                        self.validate_text.insert("end", f"  - {err}\n")
                    self.validate_text.insert("end", "\n")
                if warnings_:
                    self.validate_text.insert("end", "Warnings:\n", "warn")
                    for warn in warnings_:
                        self.validate_text.insert("end", f"  - {warn}\n")
                    self.validate_text.insert("end", "\n")
                if info:
                    self.validate_text.insert("end", "Information:\n", "info")
                    for msg in info:
                        self.validate_text.insert("end", f"  - {msg}\n")
                    self.validate_text.insert("end", "\n")
                if ok:
                    self.validate_text.insert("end", "✔ Checklist is STIG Viewer compatible.\n", "ok")
                else:
                    self.validate_text.insert("end", "✘ Checklist has errors that must be resolved.\n", "error")

            self.validate_status = "Validating…"
            self._async(work, done)

        # ------------------------------------------------------------ menu actions
        def _save_preset(self):
            name = simpledialog.askstring("Save Preset", "Preset name:")
            if not name:
                return
            preset = {
                "xccdf": self.create_xccdf.get(),
                "asset": self.create_asset.get(),
                "ip": self.create_ip.get(),
                "mac": self.create_mac.get(),
                "mark": self.create_mark.get(),
                "apply_boilerplate": self.create_bp.get(),
            }
            try:
                self.presets.save(name, preset)
                messagebox.showinfo("Preset saved", f"Preset '{name}' saved.")
            except Exception as exc:
                messagebox.showerror("Preset error", str(exc))

        def _load_preset(self):
            names = self.presets.list()
            if not names:
                messagebox.showinfo("No presets", "No presets available.")
                return
            name = simpledialog.askstring("Load Preset", f"Available presets:\n{', '.join(names)}\n\nEnter name:")
            if not name:
                return
            preset = self.presets.load(name)
            if not preset:
                messagebox.showerror("Preset error", f"Preset '{name}' not found.")
                return
            self.create_xccdf.set(preset.get("xccdf", ""))
            self.create_asset.set(preset.get("asset", ""))
            self.create_ip.set(preset.get("ip", ""))
            self.create_mac.set(preset.get("mac", ""))
            self.create_mark.set(preset.get("mark", "CUI"))
            self.create_bp.set(bool(preset.get("apply_boilerplate", False)))
            messagebox.showinfo("Preset loaded", f"Preset '{name}' loaded.")

        def _export_history(self):
            path = filedialog.asksaveasfilename(
                title="Export history",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return

            def work():
                self.proc.history.export(path)
                return path

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Export error", str(result))
                else:
                    messagebox.showinfo("History export", f"History exported to {result}")

            self._async(work, done)

        def _import_history(self):
            path = filedialog.askopenfilename(title="Import history", filetypes=[("JSON Files", "*.json")])
            if not path:
                return

            def work():
                return self.proc.history.imp(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Import error", str(result))
                else:
                    messagebox.showinfo("History import", f"Imported {result} history entries.")

            self._async(work, done)

        def _export_boiler(self):
            path = filedialog.asksaveasfilename(
                title="Export boilerplates",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return
            try:
                self.proc.boiler.export(path)
                messagebox.showinfo("Boilerplates", f"Boilerplates exported to {path}")
            except Exception as exc:
                messagebox.showerror("Boilerplate error", str(exc))

        def _import_boiler(self):
            path = filedialog.askopenfilename(title="Import boilerplates", filetypes=[("JSON Files", "*.json")])
            if not path:
                return
            try:
                self.proc.boiler.imp(path)
                messagebox.showinfo("Boilerplates", "Custom boilerplates imported.")
            except Exception as exc:
                messagebox.showerror("Boilerplate error", str(exc))

        def _cleanup_old(self):
            try:
                backups, logs = Cfg.cleanup_old()
                messagebox.showinfo("Cleanup", f"Removed {backups} backup(s) and {logs} log(s).")
            except Exception as exc:
                messagebox.showerror("Cleanup error", str(exc))

        def _about(self):
            messagebox.showinfo(
                "About",
                f"{APP_NAME}\nVersion: {VERSION}\nBuild: {BUILD_DATE}\n"
                f"STIG Viewer: {STIG_VIEWER_VERSION}\n"
                f"Python: {platform.python_version()}\n"
                f"Platform: {platform.system()} {platform.release()}",
            )

        # --------------------------------------------------------------- helpers
        def _refresh_evidence_summary(self):
            summary = self.evidence.summary()
            text = (
                f"Vulnerabilities with evidence: {summary['vulnerabilities']}\n"
                f"Total files: {summary['files']}\n"
                f"Total size: {summary['size_mb']:.2f} MB ({summary['size_bytes']} bytes)\n"
                f"Storage path: {summary['storage']}"
            )
            self.evid_summary.set(text)

        def _close(self):
            self.root.destroy()

        def run(self):
            self.root.mainloop()


# ──────────────────────────────────────────────────────────────────────────────
# UTILITY
# ──────────────────────────────────────────────────────────────────────────────


def ensure_default_boilerplates() -> None:
    if Cfg.BOILERPLATE_FILE and not Cfg.BOILERPLATE_FILE.exists():
        BP().export(Cfg.BOILERPLATE_FILE)
        LOG.i(f"Default boilerplate templates saved to {Cfg.BOILERPLATE_FILE}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    ensure_default_boilerplates()
    ok, err_list = Cfg.check()
    if not ok:
        for err in err_list:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{VERSION}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--gui", action="store_true", help="Launch graphical interface")

    create_group = parser.add_argument_group("Create CKL from XCCDF")
    create_group.add_argument("--create", action="store_true", help="Create CKL from XCCDF")
    create_group.add_argument("--xccdf", help="XCCDF XML file")
    create_group.add_argument("--asset", help="Asset name")
    create_group.add_argument("--out", help="Output CKL path")
    create_group.add_argument("--ip", help="Asset IP")
    create_group.add_argument("--mac", help="Asset MAC")
    create_group.add_argument("--role", default="None", help="Asset role")
    create_group.add_argument("--marking", default="CUI", help="Asset marking")
    create_group.add_argument("--apply-boilerplate", action="store_true", help="Apply boilerplate templates")
    create_group.add_argument("--dry-run", action="store_true", help="Dry run (no output written)")

    merge_group = parser.add_argument_group("Merge Checklists")
    merge_group.add_argument("--merge", action="store_true", help="Merge checklists preserving history")
    merge_group.add_argument("--base", help="Base checklist")
    merge_group.add_argument("--histories", nargs="+", help="Historical checklists to merge")
    merge_group.add_argument("--merge-out", help="Merged output CKL")
    merge_group.add_argument("--no-preserve-history", action="store_true", help="Disable history preservation")
    merge_group.add_argument("--no-boilerplate", action="store_true", help="Disable boilerplate application")
    merge_group.add_argument("--merge-dry-run", action="store_true", help="Dry run (no output written)")

    extract_group = parser.add_argument_group("Extract Fixes")
    extract_group.add_argument("--extract", help="XCCDF file to extract fixes from")
    extract_group.add_argument("--outdir", help="Output directory for fixes")
    extract_group.add_argument("--no-json", action="store_true", help="Do not export JSON")
    extract_group.add_argument("--no-csv", action="store_true", help="Do not export CSV")
    extract_group.add_argument("--no-bash", action="store_true", help="Do not export Bash script")
    extract_group.add_argument("--no-ps", action="store_true", help="Do not export PowerShell script")
    extract_group.add_argument("--script-dry-run", action="store_true", help="Generate scripts in dry-run mode")

    result_group = parser.add_argument_group("Apply Remediation Results")
    result_group.add_argument("--apply-results", help="Results JSON file to import")
    result_group.add_argument("--checklist", help="Checklist to update")
    result_group.add_argument("--results-out", help="Updated checklist output path")
    result_group.add_argument("--no-auto-status", action="store_true", help="Do not auto-mark successes as NotAFinding")
    result_group.add_argument("--results-dry-run", action="store_true", help="Dry run (no output written)")

    evidence_group = parser.add_argument_group("Evidence Management")
    evidence_group.add_argument("--import-evidence", nargs=2, metavar=("VID", "FILE"), help="Import evidence file")
    evidence_group.add_argument("--evidence-desc", help="Evidence description")
    evidence_group.add_argument("--evidence-cat", default="general", help="Evidence category")
    evidence_group.add_argument("--export-evidence", help="Export all evidence to directory")
    evidence_group.add_argument("--package-evidence", help="Create evidence ZIP package")
    evidence_group.add_argument("--import-evidence-package", help="Import evidence from package")

    history_group = parser.add_argument_group("History Management")
    history_group.add_argument("--export-history", help="Export history JSON")
    history_group.add_argument("--import-history", help="Import history JSON")

    parser.add_argument("--validate", help="Validate checklist compatibility")

    args = parser.parse_args(argv)

    if args.verbose:
        LOG.log.setLevel(logging.DEBUG)

    try:
        if args.gui:
            if not Deps.HAS_TKINTER:
                print("ERROR: tkinter not available. Install python3-tk.", file=sys.stderr)
                return 1
            gui = GUI()
            gui.run()
            return 0

        proc = Proc()

        if args.create:
            if not (args.xccdf and args.asset and args.out):
                parser.error("--create requires --xccdf, --asset, and --out")
            result = proc.xccdf_to_ckl(
                args.xccdf,
                args.out,
                args.asset,
                ip=args.ip or "",
                mac=args.mac or "",
                role=args.role,
                marking=args.marking,
                dry=args.dry_run,
                apply_boilerplate=args.apply_boilerplate,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.merge:
            if not (args.base and args.histories and args.merge_out):
                parser.error("--merge requires --base, --histories, and --merge-out")
            result = proc.merge(
                args.base,
                args.histories,
                args.merge_out,
                preserve_history=not args.no_preserve_history,
                apply_boilerplate=not args.no_boilerplate,
                dry=args.merge_dry_run,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0

        if args.extract:
            if not args.outdir:
                parser.error("--extract requires --outdir")

            extractor = FixExt(args.extract)
            extractor.extract()
            outdir = Path(args.outdir)
            outdir.mkdir(parents=True, exist_ok=True)

            if not args.no_json:
                extractor.to_json(outdir / "fixes.json")
            if not args.no_csv:
                extractor.to_csv(outdir / "fixes.csv")
            if not args.no_bash:
                extractor.to_bash(outdir / "remediate.sh", dry_run=args.script_dry_run)
            if not args.no_ps:
                extractor.to_powershell(outdir / "Remediate.ps1", dry_run=args.script_dry_run)

            print(json.dumps(extractor.stats_summary(), indent=2, ensure_ascii=False))
            return 0


        if args.apply_results:
            if not (args.checklist and args.results_out):
                parser.error("--apply-results requires --checklist and --results-out")

            # ═══ ENHANCED: Support multiple result files ═══
            result_files = args.apply_results if isinstance(args.apply_results, list) else [args.apply_results]

            processor = FixResPro()
            total_loaded = 0
            total_skipped = 0
            failed_files = []

            print(f"[INFO] Processing {len(result_files)} result file(s)...", file=sys.stderr)

            for idx, result_file in enumerate(result_files, 1):
                try:
                    print(f"[{idx}/{len(result_files)}] Loading {Path(result_file).name}...", file=sys.stderr)
                    imported, skipped = processor.load(result_file)
                    total_loaded += imported
                    total_skipped += skipped
                    print(f"  ✓ Loaded {imported} results (skipped {skipped})", file=sys.stderr)
                except Exception as exc:
                    print(f"  ✘ Failed: {exc}", file=sys.stderr)
                    failed_files.append({"file": str(result_file), "error": str(exc)})
                    continue

            if not processor.results:
                print(f"[ERROR] No valid results loaded from any file", file=sys.stderr)
                return 1

            print(f"\n[INFO] Applying {len(processor.results)} unique results to checklist...", file=sys.stderr)

            # Apply to checklist
            result = processor.update_ckl(
                args.checklist,
                args.results_out,
                auto_status=not args.no_auto_status,
                dry=args.results_dry_run,
            )

            # Add batch statistics
            result['batch_stats'] = {
                'files_total': len(result_files),
                'files_failed': len(failed_files),
                'results_loaded': total_loaded,
                'results_skipped': total_skipped,
                'unique_vulns': len(processor.results),
            }

            if failed_files:
                result['failed_files'] = failed_files

            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if len(failed_files) == 0 else 2  # Exit code 2 if some files failed


        evidence_mgr = EvidenceMgr()

        if args.import_evidence:
            vid, path = args.import_evidence
            dest = evidence_mgr.import_file(
                vid,
                path,
                description=args.evidence_desc or "",
                category=args.evidence_cat or "general",
            )
            print(f"Evidence imported: {dest}")
            return 0

        if args.export_evidence:
            count = evidence_mgr.export_all(args.export_evidence)
            print(f"Exported {count} evidence files to {args.export_evidence}")
            return 0

        if args.package_evidence:
            archive = evidence_mgr.package(args.package_evidence)
            print(f"Evidence package created: {archive}")
            return 0

        if args.import_evidence_package:
            count = evidence_mgr.import_package(args.import_evidence_package)
            print(f"Imported {count} evidence files from package")
            return 0

        if args.export_history:
            proc.history.export(args.export_history)
            print(f"History exported to {args.export_history}")
            return 0

        if args.import_history:
            count = proc.history.imp(args.import_history)
            print(f"Imported {count} history entries")
            return 0

        if args.validate:
            ok, errors, warnings_, info = proc.validator.validate(args.validate)
            print(json.dumps({"ok": ok, "errors": errors, "warnings": warnings_, "info": info}, indent=2))
            return 0 if ok else 1

        parser.print_help()
        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as exc:
        LOG.e(f"Fatal error: {exc}", exc=True)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        GLOBAL.cleanup()
        gc.collect()


if __name__ == "__main__":
    sys.exit(main())
