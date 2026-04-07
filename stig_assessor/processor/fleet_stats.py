"""Fleet Statistics Processor.
Aggregates compliance metrics across multiple STIG checklists.
"""

import os
import shutil
import tempfile
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Union

from stig_assessor.core.logging import LOG
from stig_assessor.processor.processor import Proc


class FleetStats:
    """Calculates fleet-wide compliance by aggregating multiple checklists.

    This processor runs dynamically across entire active enclaves by extracting
    and analyzing zip archives or flat directories containing hundreds of CKLs.
    """

    def __init__(self) -> None:
        """Initialize the FleetStats processor."""
        self.proc = Proc()

    def process_directory(self, dir_path: Union[str, Path]) -> Dict[str, Any]:
        """Recursively process all .ckl/.cklb files in a directory.

        Args:
            dir_path: Path to the directory containing checklists.

        Returns:
            Dict containing aggregated compliance metrics.
        """
        dir_path = Path(dir_path)
        if not dir_path.exists() or not dir_path.is_dir():
            LOG.w(f"Directory not found for fleet stats: {dir_path}")
            return self._empty_fleet()

        files = []
        for root, _, filenames in os.walk(dir_path):
            for name in filenames:
                if name.lower().endswith((".ckl", ".cklb")):
                    files.append(Path(root) / name)

        return self.process_files(files)

    def process_zip(self, zip_path: Union[str, Path]) -> Dict[str, Any]:
        """Extract and process a ZIP containing checklists.

        Args:
            zip_path: Path to the .zip archive containing checklists.

        Returns:
            Dict containing aggregated compliance stats, identical to process_directory.
        """
        zip_path = Path(zip_path)
        if not zip_path.exists() or not zipfile.is_zipfile(zip_path):
            LOG.w(f"Invalid ZIP for fleet stats: {zip_path}")
            return self._empty_fleet()

        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            return self.process_directory(temp_dir)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def process_files(self, file_paths: List[Union[str, Path]]) -> Dict[str, Any]:
        """Process multiple CKL/CKLB files and aggregate stats concurrently.

        Leverages a ThreadPoolExecutor to accelerate IO-bound XML parsing across cores.

        Args:
            file_paths: A list of paths pointing to individual checklist files.

        Returns:
            A nested Dict consisting of overall summary, severity breakdown, and
            granular asset lists ranked by compliance percentages.
        """
        fleet = self._empty_fleet()
        valid_files = [
            Path(p)
            for p in file_paths
            if Path(p).exists() and Path(p).suffix.lower() in (".ckl", ".cklb")
        ]

        if not valid_files:
            return fleet

        LOG.i(f"Fleet processing {len(valid_files)} checklists...")

        def process_single(path: Path) -> Dict:
            try:
                # Use generate_stats which gives us top-level info
                stats = self.proc.generate_stats(str(path), output_format="json")
                return stats
            except Exception as e:
                LOG.e(f"Failed to process {path.name} in fleet stats: {e}")
                return {}

        import gc

        # Use ThreadPoolExecutor for concurrent parsing speeds
        max_workers = min(32, os.cpu_count() or 4)
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # We process in chunks to manually sweep GC and prevent OOM on legacy VMs
            chunk_size = 50
            for i in range(0, len(valid_files), chunk_size):
                chunk = valid_files[i: i + chunk_size]
                results.extend(list(executor.map(process_single, chunk)))
                gc.collect()

        for stats in results:
            if not stats:
                continue
            fleet["total_assets"] += 1
            fleet["total_vulns"] += stats.get("total_vulns", 0)
            fleet["reviewed"] += stats.get("reviewed", 0)
            fleet["compliant"] += stats.get("compliant", 0)

            for status, count in stats.get("by_status", {}).items():
                fleet["by_status"][status] += count

            for sev, count in stats.get("by_severity", {}).items():
                fleet["by_severity"][sev] += count

            fleet["asset_compliance"].append(
                {
                    "file": stats.get("file", "unknown"),
                    "compliance_pct": stats.get("compliance_pct", 0),
                    "compliant": stats.get("compliant", 0),
                    "reviewed": stats.get("reviewed", 0),
                    "total": stats.get("total_vulns", 0),
                }
            )

        if fleet["reviewed"] > 0:
            fleet["compliance_pct"] = (fleet["compliant"] / fleet["reviewed"]) * 100
        else:
            fleet["compliance_pct"] = 0.0

        # Reformat defaultdicts for JSON serialization
        fleet["by_status"] = dict(fleet["by_status"])
        fleet["by_severity"] = dict(fleet["by_severity"])

        # Sort asset_compliance descending
        fleet["asset_compliance"] = sorted(
            fleet["asset_compliance"],
            key=lambda x: x["compliance_pct"],
            reverse=True,
        )

        return fleet

    def _empty_fleet(self) -> Dict[str, Any]:
        return {
            "total_assets": 0,
            "total_vulns": 0,
            "reviewed": 0,
            "compliant": 0,
            "compliance_pct": 0.0,
            "by_status": defaultdict(int),
            "by_severity": defaultdict(int),
            "asset_compliance": [],
        }
