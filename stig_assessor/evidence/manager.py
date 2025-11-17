"""Evidence file lifecycle management.

This module provides the EvidenceMgr class for managing evidence files
associated with STIG vulnerabilities, including import, export, and packaging.

Source Lines: 4338-4592 (STIG_Script.py)
Team: 9 - Evidence Management
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Any, Union
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
import json
import threading
import hashlib
import shutil
import tempfile
import zipfile
import re
import os

from stig_assessor.evidence.models import EvidenceMeta


# Constants (from STIG_Script.py)
CHUNK_SIZE = 8192  # For file I/O operations


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
        # Import dependencies here to avoid circular imports
        try:
            from stig_assessor.core.config import Cfg
            self.base = Cfg.EVIDENCE_DIR
        except ImportError:
            # Fallback for when core module isn't available yet
            from pathlib import Path
            home = Path.home()
            self.base = home / ".stig_assessor" / "evidence"
            self.base.mkdir(parents=True, exist_ok=True)

        self.meta_file = self.base / "meta.json"
        self._meta: Dict[str, List[EvidenceMeta]] = defaultdict(list)
        self._lock = threading.RLock()
        self._load()

    # ----------------------------------------------------------------------- load
    def _load(self) -> None:
        """Load evidence metadata from disk.

        Reads meta.json and populates internal metadata dictionary.
        Silently ignores errors (creates empty metadata on first run).
        """
        if not self.meta_file.exists():
            return

        with suppress(Exception):
            try:
                from stig_assessor.io.file_ops import FO
                data = json.loads(FO.read(self.meta_file))
            except ImportError:
                # Fallback when FO isn't available yet
                data = json.loads(self.meta_file.read_text(encoding="utf-8"))

            for vid, entries in data.items():
                try:
                    # Import sanitizer if available
                    try:
                        from stig_assessor.xml.sanitizer import San
                        vid = San.vuln(vid)
                    except ImportError:
                        vid = str(vid).strip()
                except Exception:
                    continue

                self._meta[vid] = []
                for entry in entries:
                    with suppress(Exception):
                        meta = EvidenceMeta.from_dict(entry)
                        self._meta[vid].append(meta)

    # ----------------------------------------------------------------------- save
    def _save(self) -> None:
        """Save evidence metadata to disk.

        Writes metadata to meta.json using atomic write if available.
        """
        payload = {
            vid: [entry.as_dict() for entry in entries]
            for vid, entries in self._meta.items()
        }

        try:
            from stig_assessor.io.file_ops import FO
            with FO.atomic(self.meta_file) as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
        except ImportError:
            # Fallback when FO isn't available yet
            with self.meta_file.open('w', encoding='utf-8') as handle:
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
        # Import dependencies
        try:
            from stig_assessor.xml.sanitizer import San
            from stig_assessor.core.logging import LOG
            from stig_assessor.exceptions import FileError
        except ImportError:
            # Fallback implementations
            class FileError(Exception):
                pass

            class San:
                @staticmethod
                def vuln(s):
                    return str(s).strip()

                @staticmethod
                def path(p, exist=False, file=False):
                    p = Path(p)
                    if exist and not p.exists():
                        raise FileError(f"Path does not exist: {p}")
                    if file and p.exists() and not p.is_file():
                        raise FileError(f"Path is not a file: {p}")
                    return p

            class LOG:
                @staticmethod
                def ctx(**kwargs):
                    pass

                @staticmethod
                def i(msg):
                    print(f"INFO: {msg}")

                @staticmethod
                def w(msg):
                    print(f"WARN: {msg}")

                @staticmethod
                def clear():
                    pass

        vid = San.vuln(vid)
        file_path = San.path(file_path, exist=True, file=True)

        LOG.ctx(op="import_evidence", vid=vid)
        LOG.i(f"Importing evidence for {vid}: {file_path}")

        dest_dir = self.base / vid

        # Compute hash BEFORE checking for duplicates to avoid unnecessary I/O
        file_size = file_path.stat().st_size
        file_hash = hashlib.sha256()

        # Add progress indication for large files
        if file_size > 10 * 1024 * 1024:  # 10MB+
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
                        LOG.clear()
                        return existing_path
                    else:
                        LOG.w(f"Duplicate entry exists but file missing: {existing_path}")
                        # Remove stale metadata entry
                        self._meta[vid].remove(entry)
                        break

            # Not a duplicate, proceed with import
            dest_dir.mkdir(parents=True, exist_ok=True)
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
        # Import sanitizer if available
        try:
            from stig_assessor.xml.sanitizer import San
            from stig_assessor.core.logging import LOG
            dest_dir = San.path(dest_dir, mkpar=True, dir=True)
        except ImportError:
            dest_dir = Path(dest_dir)
            dest_dir.mkdir(parents=True, exist_ok=True)

            class LOG:
                @staticmethod
                def ctx(**kwargs):
                    pass

                @staticmethod
                def i(msg):
                    print(f"INFO: {msg}")

                @staticmethod
                def clear():
                    pass

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

        # Export metadata
        metadata_path = dest_dir / "evidence_meta.json"
        try:
            from stig_assessor.io.file_ops import FO
            with FO.atomic(metadata_path) as handle:
                json.dump(
                    {vid: [entry.as_dict() for entry in entries]
                     for vid, entries in self._meta.items()},
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )
        except ImportError:
            with metadata_path.open('w', encoding='utf-8') as handle:
                json.dump(
                    {vid: [entry.as_dict() for entry in entries]
                     for vid, entries in self._meta.items()},
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )

        LOG.i(f"Exported {copied} evidence files")
        LOG.clear()
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
        # Import sanitizer if available
        try:
            from stig_assessor.xml.sanitizer import San
            from stig_assessor.core.logging import LOG
            from stig_assessor.io.file_ops import FO
            zip_path = San.path(zip_path, mkpar=True)
        except ImportError:
            zip_path = Path(zip_path)
            zip_path.parent.mkdir(parents=True, exist_ok=True)

            class LOG:
                @staticmethod
                def ctx(**kwargs):
                    pass

                @staticmethod
                def i(msg):
                    print(f"INFO: {msg}")

                @staticmethod
                def clear():
                    pass

            class FO:
                @staticmethod
                def zip(zip_path, files, base="evidence"):
                    # Simple ZIP creation
                    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for arc_name, source_path in files.items():
                            zf.write(source_path, f"{base}/{arc_name}")
                    return zip_path

        LOG.ctx(op="package_evidence")
        LOG.i(f"Packaging evidence into {zip_path}")

        files: Dict[str, Path] = {}
        with self._lock:
            for vid, entries in self._meta.items():
                for entry in entries:
                    source = self.base / vid / entry.filename
                    if source.exists():
                        files[f"{vid}/{entry.filename}"] = source

        # Create temporary metadata file
        tmp_meta = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        meta_path = Path(tmp_meta.name)
        with tmp_meta:
            json.dump(
                {vid: [entry.as_dict() for entry in entries]
                 for vid, entries in self._meta.items()},
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
        # Import dependencies
        try:
            from stig_assessor.xml.sanitizer import San
            from stig_assessor.core.logging import LOG
            from stig_assessor.exceptions import ValidationError
            package = San.path(package, exist=True, file=True)
        except ImportError:
            package = Path(package)
            if not package.exists():
                raise FileNotFoundError(f"Package not found: {package}")

            class ValidationError(Exception):
                pass

            class San:
                @staticmethod
                def vuln(s):
                    return str(s).strip()

            class LOG:
                @staticmethod
                def ctx(**kwargs):
                    pass

                @staticmethod
                def i(msg):
                    print(f"INFO: {msg}")

                @staticmethod
                def clear():
                    pass

        LOG.ctx(op="import_evidence_package", file=package.name)
        LOG.i("Importing evidence package")

        extracted = 0
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with zipfile.ZipFile(package, "r") as archive:
                # Security: Validate all archive members before extraction
                # to prevent path traversal attacks (CVE-2007-4559)
                for member in archive.namelist():
                    # Normalize the path and check for traversal attempts
                    member_path = Path(member)
                    if member_path.is_absolute():
                        raise ValidationError(f"Archive contains absolute path: {member}")

                    # Check for parent directory references
                    if ".." in member_path.parts:
                        raise ValidationError(f"Archive contains path traversal: {member}")

                    # Verify resolved path stays within extraction directory
                    target_path = (tmp_path / member).resolve()
                    try:
                        target_path.relative_to(tmp_path.resolve())
                    except ValueError:
                        raise ValidationError(
                            f"Archive path escapes extraction directory: {member}"
                        )

                # Safe to extract after validation
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
                except Exception:
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
                    self.import_file(vid, file, description=description, category=category)
                    extracted += 1

        LOG.i(f"Imported {extracted} evidence files from package")
        LOG.clear()
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
                entry.file_size
                for entries in self._meta.values()
                for entry in entries
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
