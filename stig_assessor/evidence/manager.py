"""Evidence file lifecycle management.

This module provides the EvidenceMgr class for managing evidence files
associated with STIG vulnerabilities, including import, export, and packaging.

Source Lines: 4338-4592 (STIG_Script.py)
Team: 9 - Evidence Management
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import zipfile
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import CHUNK_SIZE, LARGE_EVIDENCE_THRESHOLD
from stig_assessor.core.logging import LOG
from stig_assessor.evidence.models import EvidenceMeta
from stig_assessor.exceptions import ValidationError
from stig_assessor.io.file_ops import FO
from stig_assessor.xml.sanitizer import San

SAFE_FILENAME_RE = re.compile(r"[^\w.-]")


class EvidenceMgr:
    """Evidence file lifecycle manager (Singleton).

    Manages evidence files associated with STIG vulnerabilities:
    - Import files with hash-based deduplication
    - Export all evidence to directory
    - Package evidence into ZIP archives
    - Import evidence packages
    - Track metadata in JSON format

    Thread-safe: Yes (uses RLock for metadata operations)

    Example:
        >>> mgr = EvidenceMgr()
        >>> mgr.import_file("V-123456", Path("screenshot.png"),
        ...                 description="System config", category="screenshot")
        >>> mgr.export_all(Path("/output"))
        >>> mgr.package(Path("evidence.zip"))
    """

    def __init__(self):
        """Initialize evidence manager.

        Loads existing metadata from disk if available.
        Creates evidence directory structure as needed.
        """
        self.base = Cfg.EVIDENCE_DIR

        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.meta_file = self.base / "meta.json"
        self._meta: Dict[str, List[EvidenceMeta]] = defaultdict(list)
        self._lock = threading.RLock()
        self._io_lock = threading.Lock()
        self._load()

    # ----------------------------------------------------------------------- load
    def _load(self) -> None:
        """Load evidence metadata from disk.

        Reads meta.json and populates internal metadata dictionary.
        Silently ignores errors (creates empty metadata on first run).
        """
        if not self.meta_file.exists():
            return

        with suppress(OSError, ValueError):
            data = json.loads(FO.read(self.meta_file))
            for vid, entries in data.items():
                try:
                    vid = San.vuln(vid)
                except ValidationError as exc:
                    LOG.w(
                        f"Skipping badly formed VID '{vid}' during evidence meta load: {exc}"
                    )
                    continue

                self._meta[vid] = []
                if not isinstance(entries, list):
                    continue
                for entry in entries[:100]:
                    with suppress(ValueError, TypeError):
                        meta = EvidenceMeta.from_dict(entry)
                        self._meta[vid].append(meta)

    # ----------------------------------------------------------------------- save
    def _save(self) -> None:
        """Save evidence metadata to disk.

        Writes metadata to meta.json using atomic write if available.
        Performs actual IO outside the metadata lock to prevent thread bottlenecks.
        """
        with self._lock:
            payload = {
                vid: [entry.as_dict() for entry in entries]
                for vid, entries in self._meta.items()
            }

        with self._io_lock:
            with FO.atomic(self.meta_file) as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)

    # ----------------------------------------------------------------------- import
    def import_file(
        self,
        vid: str,
        file_path: Union[str, Path],
        *,
        description: str = "",
        category: str = "general",
    ) -> Path:
        """Import evidence file for a vulnerability.

        Args:
            vid: Vulnerability ID (e.g., "V-123456")
            file_path: Source file path
            description: Human-readable description
            category: Evidence category (e.g., "config", "screenshot")

        Returns:
            Path to imported evidence file

        Raises:
            FileError: If file doesn't exist or import fails
            ValidationError: If VID is invalid

        Note:
            - Performs hash-based deduplication
            - Files are renamed with timestamp prefix
            - Original file is copied (not moved)
        """
        vid = San.vuln(vid)
        file_path = San.path(file_path, exist=True, file=True)

        with LOG.context(op="import_evidence", vid=vid):
            LOG.i(f"Importing evidence for {vid}: {file_path}")

            dest_dir = self.base / vid

            file_size = file_path.stat().st_size
            file_hash = hashlib.sha256()

            if file_size > LARGE_EVIDENCE_THRESHOLD:
                LOG.i(f"Computing hash for large file ({file_size} bytes)...")

            with open(file_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                    file_hash.update(chunk)

            digest = file_hash.hexdigest()

            # Check for duplicates BEFORE copying (saves I/O)
            with self._lock:
                for entry in self._meta[vid]:
                    if entry.file_hash == digest:
                        LOG.w("Duplicate evidence detected (by hash), skipping copy")
                        existing_path = dest_dir / entry.filename
                        if existing_path.exists():
                            return existing_path
                        else:
                            LOG.w(
                                f"Duplicate entry exists but file missing: {existing_path}"
                            )
                            self._meta[vid].remove(entry)
                            break

            # Not a duplicate, proceed with import outside lock for fast mutox
            dest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_name = SAFE_FILENAME_RE.sub("_", file_path.name)
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
            with self._lock:
                self._meta[vid].append(meta)
                
            self._save()

            LOG.i(f"Evidence imported to {dest}")
            return dest

    # ----------------------------------------------------------------------- export
    def export_all(self, dest_dir: Union[str, Path]) -> int:
        """Export all evidence to directory.

        Args:
            dest_dir: Output directory (created if doesn't exist)

        Returns:
            Number of files exported

        Note:
            - Creates subdirectories for each VID
            - Exports metadata to evidence_meta.json
            - Preserves file timestamps (copy2)
        """
        dest_dir = San.path(dest_dir, mkpar=True, dir=True)

        with LOG.context(op="export_evidence"):
            LOG.i(f"Exporting evidence to {dest_dir}")

            copied = 0
            # Pull meta out of lock to avoid blocking IO
            with self._lock:
                meta_snapshot = {
                    vid: list(entries) for vid, entries in self._meta.items()
                }

            for vid, entries in meta_snapshot.items():
                source_dir = self.base / vid
                if not source_dir.exists():
                    continue
                target_vid_dir = dest_dir / vid
                target_vid_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                for entry in entries:
                    source_file = source_dir / entry.filename
                    if not source_file.exists():
                        continue
                    shutil.copy2(source_file, target_vid_dir / entry.filename)
                    copied += 1

            # Export metadata
            metadata_path = dest_dir / "evidence_meta.json"
            with FO.atomic(metadata_path) as handle:
                json.dump(
                    {
                        vid: [entry.as_dict() for entry in entries]
                        for vid, entries in meta_snapshot.items()
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )

            LOG.i(f"Exported {copied} evidence files")
            return copied

    # ----------------------------------------------------------------------- package
    def package(self, zip_path: Union[str, Path]) -> Path:
        """Package all evidence into ZIP file.

        Args:
            zip_path: Output ZIP file path

        Returns:
            Path to created ZIP file

        Raises:
            FileError: If packaging fails

        Note:
            - Includes meta.json in ZIP root
            - Files organized as VID/filename in archive
            - Uses ZIP_DEFLATED compression
        """
        zip_path = San.path(zip_path, mkpar=True)

        with LOG.context(op="package_evidence"):
            LOG.i(f"Packaging evidence into {zip_path}")

            files: Dict[str, Path] = {}
            with self._lock:
                meta_snapshot = {
                    vid: list(entries) for vid, entries in self._meta.items()
                }

            for vid, entries in meta_snapshot.items():
                for entry in entries:
                    source = self.base / vid / entry.filename
                    if source.exists():
                        files[f"{vid}/{entry.filename}"] = source

            # Create temporary metadata file
            tmp_meta = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
            meta_path = Path(tmp_meta.name)
            with tmp_meta:
                json.dump(
                    {
                        vid: [entry.as_dict() for entry in entries]
                        for vid, entries in meta_snapshot.items()
                    },
                    tmp_meta,
                    indent=2,
                    ensure_ascii=False,
                )

            files["meta.json"] = meta_path

            try:
                archive = FO.zip(zip_path, files, base="evidence")
            finally:
                with suppress(OSError):
                    meta_path.unlink()

            LOG.i(f"Evidence package created: {archive}")
            return archive

    # ----------------------------------------------------------------------- import pkg
    def import_package(self, package: Union[str, Path]) -> int:
        """Import evidence from ZIP package.

        Args:
            package: ZIP file path

        Returns:
            Number of files imported

        Raises:
            ValidationError: If package contains path traversal attempts
            FileError: If package is invalid

        Security:
            - Validates all archive members for path traversal (CVE-2007-4559)
            - Rejects absolute paths
            - Rejects parent directory references (..)
        """
        package = San.path(package, exist=True, file=True)

        with LOG.context(op="import_evidence_package", file=package.name):
            LOG.i("Importing evidence package")

            extracted = 0
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)

                if hasattr(shutil, "unpack_archive") and sys.version_info >= (
                    3,
                    12,
                ):
                    shutil.unpack_archive(package, extract_dir=tmp_path, filter="data")
                else:
                    with zipfile.ZipFile(package, "r") as archive:
                        for member in archive.namelist():
                            member_path = Path(member)
                            if member_path.is_absolute() or ".." in member_path.parts:
                                raise ValidationError(
                                    f"Archive contains path traversal: {member}"
                                )
                            target_path = (tmp_path / member).resolve()
                            try:
                                target_path.relative_to(tmp_path.resolve())
                            except ValueError:
                                raise ValidationError(
                                    f"Archive path escapes extraction directory: {member}"
                                )
                        archive.extractall(tmp_path)

                # Find evidence directory
                evidence_dir = tmp_path / "evidence"
                if evidence_dir.exists():
                    meta_file = evidence_dir / "meta.json"
                else:
                    evidence_dir = tmp_path
                    meta_file = tmp_path / "meta.json"

                # Load metadata
                if meta_file.exists():
                    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
                else:
                    meta_data = {}

                # Import files
                for vid_dir in evidence_dir.iterdir():
                    if not vid_dir.is_dir():
                        continue
                    vid = vid_dir.name
                    try:
                        vid = San.vuln(vid)
                    except ValidationError as vid_err:
                        LOG.d(f"Invalid VID skipped during import: {vid_err}")
                        continue
                    for file in vid_dir.iterdir():
                        if not file.is_file():
                            continue
                        description = ""
                        category = "general"
                        # Find metadata for this file
                        for entry in meta_data.get(vid, []):
                            if entry.get("filename") == file.name:
                                description = entry.get("description", "")
                                category = entry.get("category", "general")
                                break
                        self.import_file(
                            vid,
                            file,
                            description=description,
                            category=category,
                        )
                        extracted += 1

            LOG.i(f"Imported {extracted} evidence files from package")
            return extracted

    # ----------------------------------------------------------------------- summary
    def summary(self) -> Dict[str, Any]:
        """Get evidence storage summary.

        Returns:
            Dictionary with:
                - vulnerabilities: Number of VIDs with evidence
                - files: Total number of evidence files
                - size_bytes: Total size in bytes
                - size_mb: Total size in megabytes
                - storage: Evidence directory path
        """
        with self._lock:
            total_files = sum(len(entries) for entries in self._meta.values())
            total_size = sum(
                entry.file_size for entries in self._meta.values() for entry in entries
            )
            return {
                "vulnerabilities": len(self._meta),
                "files": total_files,
                "size_bytes": total_size,
                "size_mb": total_size / (1024 * 1024),
                "storage": str(self.base),
            }


# Module-level singleton instance
EVIDENCE = EvidenceMgr()
