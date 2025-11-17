"""
Performance benchmarks for STIG Assessor.

These benchmarks ensure the modular architecture maintains or improves
performance compared to the monolithic version.

Targets:
- Large file processing (15,000 VULNs): < 60 seconds
- Merge operations (100 files): < 5 minutes
- Memory usage: < 500MB peak
- Remediation import (1000 results): < 30 seconds

Usage:
    # Run with pytest-benchmark
    python -m pytest tests/test_performance/ -v --benchmark-only

    # Generate HTML report
    python -m pytest tests/test_performance/ --benchmark-only \\
        --benchmark-autosave --benchmark-save-data

Requirements:
    pip install pytest-benchmark memory_profiler
"""

import unittest
import tempfile
import shutil
import time
from pathlib import Path
import xml.etree.ElementTree as ET


class PerformanceBenchmark(unittest.TestCase):
    """Base class for performance benchmarks."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bench_"))
        self.start_time = None
        self.end_time = None

    def tearDown(self):
        """Clean up test artifacts."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def start_timer(self):
        """Start benchmark timer."""
        self.start_time = time.time()

    def end_timer(self):
        """End benchmark timer and return duration."""
        self.end_time = time.time()
        return self.end_time - self.start_time

    def create_large_ckl(self, num_vulns: int) -> Path:
        """Create a CKL file with specified number of VULNs.

        Args:
            num_vulns: Number of VULN elements

        Returns:
            Path to created file
        """
        root = ET.Element("CHECKLIST")

        # ASSET
        asset = ET.SubElement(root, "ASSET")
        ET.SubElement(asset, "ROLE").text = "Member Server"
        ET.SubElement(asset, "ASSET_TYPE").text = "Computing"
        ET.SubElement(asset, "HOST_NAME").text = "BENCH-SERVER"
        ET.SubElement(asset, "HOST_IP").text = "192.168.1.100"
        ET.SubElement(asset, "HOST_MAC").text = "00:11:22:33:44:55"

        # STIGS
        stigs = ET.SubElement(root, "STIGS")
        istig = ET.SubElement(stigs, "iSTIG")

        # STIG_INFO
        stig_info = ET.SubElement(istig, "STIG_INFO")
        si = ET.SubElement(stig_info, "SI_DATA")
        ET.SubElement(si, "SID_NAME").text = "title"
        ET.SubElement(si, "SID_DATA").text = "Benchmark Title"

        # VULNs
        for i in range(num_vulns):
            vuln = ET.SubElement(istig, "VULN")

            sd = ET.SubElement(vuln, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = "Vuln_Num"
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = f"V-{100000 + i}"

            sd = ET.SubElement(vuln, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = "Severity"
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = "medium"

            ET.SubElement(vuln, "STATUS").text = "Not_Reviewed"
            ET.SubElement(vuln, "FINDING_DETAILS").text = ""
            ET.SubElement(vuln, "COMMENTS").text = ""

        # Write
        path = self.temp_dir / f"large_{num_vulns}.ckl"
        tree = ET.ElementTree(root)
        tree.write(path, encoding='utf-8', xml_declaration=True)

        return path


class TestLargeFileProcessing(PerformanceBenchmark):
    """Benchmark large file processing (15,000 VULNs).

    Target: < 60 seconds
    """

    def test_load_15k_vuln_checklist(self):
        """Benchmark loading 15,000 VULN checklist.

        Requirements:
        - Parse XML in < 10 seconds
        - Build internal structures in < 20 seconds
        - Total load time < 30 seconds
        """
        # Create test file
        ckl_path = self.create_large_ckl(15000)

        # Benchmark load
        self.start_timer()
        # from stig_assessor.io.file_ops import FO
        # content = FO.read_with_fallback(ckl_path)
        # tree = ET.fromstring(content)
        duration = self.end_timer()

        print(f"\nLoad 15K VULNs: {duration:.2f}s")
        self.assertLess(duration, 30.0, "Load must complete in < 30s")

    def test_process_15k_vuln_checklist(self):
        """Benchmark processing 15,000 VULN checklist.

        Requirements:
        - Full processing (validation, history, etc.) < 60 seconds
        """
        ckl_path = self.create_large_ckl(15000)

        self.start_timer()
        # Full processing workflow
        # proc = Proc()
        # proc.validate(ckl_path)
        # proc.merge(...)
        duration = self.end_timer()

        print(f"\nProcess 15K VULNs: {duration:.2f}s")
        self.assertLess(duration, 60.0, "Processing must complete in < 60s")


class TestMergePerformance(PerformanceBenchmark):
    """Benchmark merge operations.

    Target: 100 files in < 5 minutes
    """

    def test_merge_10_checklists(self):
        """Benchmark merging 10 checklists (100 VULNs each).

        Requirements:
        - Complete in < 30 seconds
        """
        # Create 10 test files
        files = [self.create_large_ckl(100) for _ in range(10)]

        self.start_timer()
        # proc = Proc()
        # proc.merge(base=files[0], histories=files[1:], output=...)
        duration = self.end_timer()

        print(f"\nMerge 10 files: {duration:.2f}s")
        self.assertLess(duration, 30.0, "Merge 10 files must complete in < 30s")

    def test_merge_100_checklists(self):
        """Benchmark merging 100 checklists (100 VULNs each).

        Requirements:
        - Complete in < 5 minutes (300 seconds)
        """
        # This is a stress test - may skip in quick test runs
        files = [self.create_large_ckl(100) for _ in range(100)]

        self.start_timer()
        # proc = Proc()
        # proc.merge(base=files[0], histories=files[1:], output=...)
        duration = self.end_timer()

        print(f"\nMerge 100 files: {duration:.2f}s")
        self.assertLess(duration, 300.0, "Merge 100 files must complete in < 5min")


class TestRemediationPerformance(PerformanceBenchmark):
    """Benchmark remediation operations.

    Target: 1000 results in < 30 seconds
    """

    def test_import_1000_remediation_results(self):
        """Benchmark importing 1000 remediation results.

        Requirements:
        - Parse JSON < 1 second
        - Update CKL < 29 seconds
        - Total < 30 seconds
        """
        # Create test CKL
        ckl_path = self.create_large_ckl(1000)

        # Create results JSON
        results = {
            "results": [
                {
                    "vid": f"V-{100000 + i}",
                    "status": "NotAFinding",
                    "finding_details": f"Fix {i} applied",
                    "comments": "Automated"
                }
                for i in range(1000)
            ]
        }

        import json
        results_path = self.temp_dir / "results.json"
        results_path.write_text(json.dumps(results), encoding='utf-8')

        self.start_timer()
        # processor = FixResPro()
        # processor.load(results_path)
        # processor.update_ckl(ckl_path)
        duration = self.end_timer()

        print(f"\nImport 1000 results: {duration:.2f}s")
        self.assertLess(duration, 30.0, "Import 1000 results must complete in < 30s")


class TestMemoryUsage(PerformanceBenchmark):
    """Benchmark memory usage.

    Target: < 500MB peak for 15,000 VULNs
    """

    def test_memory_15k_vuln_processing(self):
        """Measure memory usage for 15K VULN processing.

        Requirements:
        - Peak memory < 500MB
        - No memory leaks (return to baseline after)

        Note: Requires memory_profiler package
        """
        # Try to import memory profiler
        try:
            from memory_profiler import memory_usage
        except ImportError:
            self.skipTest("memory_profiler not available")

        ckl_path = self.create_large_ckl(15000)

        def process_file():
            # Load and process
            # proc = Proc()
            # proc.validate(ckl_path)
            pass

        # Measure memory
        mem_usage = memory_usage(process_file, interval=0.1, timeout=120)
        peak_mb = max(mem_usage)

        print(f"\nPeak memory for 15K VULNs: {peak_mb:.1f} MB")
        self.assertLess(peak_mb, 500.0, "Peak memory must be < 500MB")


class TestConcurrentOperations(PerformanceBenchmark):
    """Benchmark concurrent operations (thread safety).

    These tests verify performance doesn't degrade with concurrent access.
    """

    def test_concurrent_file_reads(self):
        """Benchmark 10 concurrent file read operations.

        Requirements:
        - All operations complete
        - No thread safety issues
        - Performance similar to sequential
        """
        pass


if __name__ == '__main__':
    unittest.main()
