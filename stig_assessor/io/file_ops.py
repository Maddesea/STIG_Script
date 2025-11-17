"""
File operations module.

Provides atomic file operations with rollback support, encoding detection,
backup management, and secure file handling.

Team 3 Module - Dependencies:
- core/* (Team 1): Will provide Cfg, GLOBAL, LOG, Deps
- xml/* (Team 2): Will provide San (sanitizer)
- exceptions: STIGError hierarchy (already available)
- core/constants: File limits and encodings (already available)
"""

from __future__ import annotations
import os
import re
import shutil
import tempfile
import time
import zipfile
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, IO, List, Optional, Tuple, Union

# XML imports
try:
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import ParseError as XMLParseError
except ImportError:
    raise ImportError("xml.etree.ElementTree is required but not available")

# Import from our package
from stig_assessor.exceptions import FileError, ValidationError, ParseError
from stig_assessor.core.constants import (
    ENCODINGS,
    LARGE_FILE_THRESHOLD,
    MAX_XML_SIZE,
    MAX_RETRIES,
    RETRY_DELAY,
)

# TODO: These will be provided by Team 1 (core infrastructure)
# For now, create placeholder references to document the interface
# When Team 1 completes their work, these imports will be:
# from stig_assessor.core.config import Cfg
# from stig_assessor.core.state import GLOBAL
# from stig_assessor.core.logging import LOG
# from stig_assessor.core.deps import Deps

# TODO: This will be provided by Team 2 (XML foundation)
# When Team 2 completes their work, this import will be:
# from stig_assessor.xml.sanitizer import San


# ──────────────────────────────────────────────────────────────────────────────
# PLACEHOLDER IMPORTS (to be replaced when Teams 1 & 2 complete)
# ──────────────────────────────────────────────────────────────────────────────

class _PlaceholderCfg:
    """Placeholder for Cfg class from Team 1."""
    BACKUP_DIR = Path.home() / ".stig_assessor" / "backups"
    IS_WIN = os.name == "nt"
    KEEP_BACKUPS = 30

    def __init__(self):
        self.BACKUP_DIR.mkdir(parents=True, exist_ok=True)

class _PlaceholderGlobal:
    """Placeholder for GlobalState from Team 1."""
    def __init__(self):
        import threading
        self.shutdown = threading.Event()
        self._temps = set()
        self._lock = threading.Lock()

    def add_temp(self, path: Path):
        with self._lock:
            self._temps.add(path)

class _PlaceholderLog:
    """Placeholder for Log class from Team 1."""
    def i(self, msg: str, **kwargs): print(f"INFO: {msg}")
    def w(self, msg: str, **kwargs): print(f"WARN: {msg}")
    def e(self, msg: str, **kwargs): print(f"ERROR: {msg}")
    def d(self, msg: str, **kwargs): print(f"DEBUG: {msg}")
    def c(self, msg: str, **kwargs): print(f"CRITICAL: {msg}")

class _PlaceholderDeps:
    """Placeholder for Deps class from Team 1."""
    HAS_DEFUSEDXML = False

class _PlaceholderSan:
    """Placeholder for San class from Team 2."""
    @staticmethod
    def path(p: Union[str, Path], mkpar: bool = False, exist: bool = False,
             file: bool = False) -> Path:
        """Placeholder path sanitizer."""
        path = Path(p) if isinstance(p, str) else p

        if mkpar and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        if exist and not path.exists():
            raise FileError(f"Path does not exist: {path}")

        if file and not path.is_file():
            raise FileError(f"Path is not a file: {path}")

        return path

# Use placeholders until Teams 1 & 2 provide real implementations
Cfg = _PlaceholderCfg()
GLOBAL = _PlaceholderGlobal()
LOG = _PlaceholderLog()
Deps = _PlaceholderDeps()
San = _PlaceholderSan()


# ──────────────────────────────────────────────────────────────────────────────
# RETRY DECORATOR
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
# FILE OPERATIONS CLASS
# ──────────────────────────────────────────────────────────────────────────────

class FO:
    """Safe file operations with atomic writes, backup management, and encoding detection.

    All write operations are atomic with automatic rollback on failure.
    Provides encoding detection for robust file reading across different formats.
    """

    @staticmethod
    @contextmanager
    @retry()
    def atomic(target: Union[str, Path], mode: str = "w", enc: str = "utf-8", bak: bool = True) -> Generator[IO, None, None]:
        """Atomic file write with automatic rollback on failure.

        Args:
            target: Target file path
            mode: File mode (w, wb, etc.)
            enc: Encoding for text mode
            bak: Create backup before writing

        Yields:
            File handle for writing

        Raises:
            FileError: On write or rollback failure
        """
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
            tmp_path = Path(tmp_name)
            GLOBAL.add_temp(tmp_path)

            # Use os.fdopen() to avoid race condition between close/open
            if "b" in mode:
                fh = os.fdopen(fd, mode)
            else:
                fh = os.fdopen(fd, mode, encoding=enc, errors="replace", newline="\n")

            try:
                yield fh

                fh.flush()
                if not Cfg.IS_WIN:
                    os.fsync(fh.fileno())
                else:
                    with suppress(Exception):
                        fh.flush()
                        os.fsync(fh.fileno())
            finally:
                # Ensure file handle is always closed, even if fsync fails
                if fh and not fh.closed:
                    fh.close()
                fh = None

            # Windows file replacement with retry logic for antivirus/indexing locks
            if Cfg.IS_WIN and target.exists():
                max_attempts = 5
                for attempt in range(max_attempts):
                    try:
                        target.unlink()
                        break
                    except PermissionError:
                        if attempt < max_attempts - 1:
                            time.sleep(0.1 * (2 ** attempt))  # Exponential backoff: 0.1, 0.2, 0.4, 0.8s
                        else:
                            LOG.w(f"Could not delete target file after {max_attempts} attempts, replace may fail")

            # Perform atomic replace with final retry for Windows file locking
            try:
                tmp_path.replace(target)
            except OSError as e:
                # Safely check for Windows error code 32 (file in use)
                winerror = getattr(e, 'winerror', None)
                if Cfg.IS_WIN and winerror == 32:
                    LOG.d("Replace failed due to file lock, retrying with delay")
                    time.sleep(1.0)  # One final longer delay
                    tmp_path.replace(target)  # Final attempt, let exception propagate if still fails
                else:
                    raise
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
                try:
                    if target.exists():
                        target.unlink()
                    shutil.copy2(str(backup_path), str(target))
                    LOG.i(f"Restored from backup: {backup_path}")
                except Exception as rollback_err:
                    LOG.c(f"CRITICAL: Rollback failed! Manual recovery needed. Backup: {backup_path}", exc=True)
                    raise FileError(f"Atomic write failed AND rollback failed: {exc}. Backup at: {backup_path}") from rollback_err
            raise FileError(f"Atomic write failed: {exc}")
        finally:
            if tmp_path and tmp_path.exists():
                with suppress(Exception):
                    tmp_path.unlink()

    @staticmethod
    def _clean_baks(stem: str) -> None:
        """Remove old backups, keeping only the most recent ones."""
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
        """Read file with automatic encoding detection.

        Tries multiple encodings to ensure successful reading.
        For large files, detects encoding from a sample first for performance.

        Args:
            path: File path to read

        Returns:
            File contents as string

        Raises:
            FileError: If file cannot be decoded with any known encoding
        """
        path = San.path(path, exist=True, file=True)
        file_size = path.stat().st_size

        # Performance optimization: for large files, detect encoding with sample first
        sample_size = min(file_size, 8192)  # Read up to 8KB for detection
        detected_encoding = None

        if file_size > LARGE_FILE_THRESHOLD:
            # Try to detect encoding from sample
            for encoding in ENCODINGS:
                try:
                    with open(path, "r", encoding=encoding, errors="strict") as handle:
                        _ = handle.read(sample_size)
                    detected_encoding = encoding
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue

        # Read full file with detected or all encodings
        encodings_to_try = [detected_encoding] if detected_encoding else ENCODINGS

        for encoding in encodings_to_try:
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
        """Parse XML file with security checks and error recovery.

        Validates file size to prevent resource exhaustion.
        For large files, recommends defusedxml for security.
        Attempts entity sanitization if initial parse fails.

        Args:
            path: XML file path

        Returns:
            ElementTree object

        Raises:
            ValidationError: If file is too large or requires defusedxml
            ParseError: If XML cannot be parsed
        """
        path = San.path(path, exist=True, file=True)

        # Security: validate file size before parsing to prevent resource exhaustion
        file_size = path.stat().st_size
        if file_size > MAX_XML_SIZE:
            raise ValidationError(f"XML file too large: {file_size} bytes (max: {MAX_XML_SIZE})")

        # Security: require defusedxml for large files to prevent XML bomb attacks
        if not Deps.HAS_DEFUSEDXML:
            if file_size > LARGE_FILE_THRESHOLD:
                raise ValidationError(
                    f"Large XML file ({file_size} bytes) requires defusedxml for safe parsing. "
                    f"Install defusedxml (pip install defusedxml) or use a smaller file. "
                    f"Without defusedxml, only files under {LARGE_FILE_THRESHOLD / 1024 / 1024:.1f}MB can be parsed."
                )
            LOG.w("Parsing without defusedxml - vulnerable to XML entity expansion attacks if file is malicious")

        try:
            return ET.parse(str(path))
        except XMLParseError as err:
            LOG.e(f"XML parse error: {err}")
            try:
                # Only read full file if it's reasonably sized
                if file_size > LARGE_FILE_THRESHOLD:
                    LOG.w(f"Large file ({file_size} bytes) requires entity sanitization, may be slow")

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
        """Create ZIP archive with atomic write.

        Args:
            out_path: Output ZIP file path
            files: Dictionary mapping archive names to source file paths
            base: Optional base directory name in archive

        Returns:
            Path to created ZIP file

        Raises:
            FileError: If no files were successfully added
        """
        out_path = San.path(out_path, mkpar=True)
        tmp_zip: Optional[Path] = None
        added = 0

        try:
            fd, tmp_name = tempfile.mkstemp(suffix=".zip", dir=out_path.parent)
            os.close(fd)
            tmp_zip = Path(tmp_name)

            failed_files: List[str] = []
            with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                for arcname, source in files.items():
                    try:
                        source_path = San.path(source, exist=True, file=True)
                        final_arcname = f"{base}/{arcname}" if base else arcname
                        archive.write(str(source_path), arcname=final_arcname)
                        added += 1
                    except Exception as exc:
                        LOG.w(f"Skipping {arcname}: {exc}")
                        failed_files.append(f"{arcname} ({exc})")

            if added == 0:
                failed_summary = "; ".join(failed_files[:3])
                raise FileError(
                    f"No files added to zip (total attempted: {len(files)}, all failed). "
                    f"First failures: {failed_summary}"
                )

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


__all__ = ["FO", "retry"]
