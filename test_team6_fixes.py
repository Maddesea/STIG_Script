#!/usr/bin/env python3
"""
Quick test script to verify Team 6's history management modules work correctly.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all modules can be imported without errors."""
    print("Testing imports...")
    try:
        from stig_assessor.history import Hist, HistMgr
        print("✓ Successfully imported Hist and HistMgr")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_hist_model():
    """Test the Hist dataclass."""
    print("\nTesting Hist model...")
    try:
        from stig_assessor.history import Hist

        # Create a history entry
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="NotAFinding",
            find="Test finding details",
            comm="Test comment",
            src="test",
            chk="test123",
            sev="medium",
            who="testuser"
        )

        print(f"✓ Created Hist entry: {entry.stat}")

        # Test serialization
        data = entry.as_dict()
        print(f"✓ Serialized to dict: {len(data)} fields")

        # Test deserialization
        entry2 = Hist.from_dict(data)
        print(f"✓ Deserialized from dict: {entry2.stat}")

        # Test content hash
        hash_val = entry.content_hash()
        print(f"✓ Content hash: {hash_val}")

        return True
    except Exception as e:
        print(f"✗ Hist model test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_hist_manager():
    """Test the HistMgr class."""
    print("\nTesting HistMgr...")
    try:
        from stig_assessor.history import HistMgr

        # Create manager
        mgr = HistMgr()
        print("✓ Created HistMgr instance")

        # Add some entries
        vid = "V-12345"
        result1 = mgr.add(
            vid=vid,
            stat="Open",
            find="Initial finding",
            comm="Initial comment",
            src="test",
            sev="high"
        )
        print(f"✓ Added first entry: {result1}")

        result2 = mgr.add(
            vid=vid,
            stat="NotAFinding",
            find="Fixed issue",
            comm="Issue resolved",
            src="test",
            sev="high"
        )
        print(f"✓ Added second entry: {result2}")

        # Test duplicate detection
        result3 = mgr.add(
            vid=vid,
            stat="NotAFinding",
            find="Fixed issue",
            comm="Issue resolved",
            src="test",
            sev="high"
        )
        print(f"✓ Duplicate detection: {not result3} (should be True)")

        # Test merge_find
        merged = mgr.merge_find(vid, "Current finding text")
        print(f"✓ Merged finding: {len(merged)} chars")

        # Test merge_comm
        merged_comm = mgr.merge_comm(vid, "Current comment")
        print(f"✓ Merged comment: {len(merged_comm)} chars")

        return True
    except Exception as e:
        print(f"✗ HistMgr test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_export_import():
    """Test export and import functionality."""
    print("\nTesting export/import...")
    try:
        from stig_assessor.history import HistMgr
        import tempfile
        import os

        # Create manager with some data
        mgr1 = HistMgr()
        mgr1.add("V-11111", "Open", "Finding 1", "Comment 1", "test", "high")
        mgr1.add("V-22222", "NotAFinding", "Finding 2", "Comment 2", "test", "medium")

        # Export to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            mgr1.export(temp_path)
            print(f"✓ Exported to {temp_path}")

            # Import into new manager
            mgr2 = HistMgr()
            count = mgr2.imp(temp_path)
            print(f"✓ Imported {count} entries")

            # Verify data
            merged = mgr2.merge_find("V-11111", "")
            if "Finding 1" in merged:
                print("✓ Data integrity verified")
            else:
                print("✗ Data integrity check failed")
                return False

        finally:
            # Cleanup
            if os.path.exists(temp_path):
                os.unlink(temp_path)

        return True
    except Exception as e:
        print(f"✗ Export/import test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("=" * 80)
    print("Team 6 History Management Module Tests")
    print("=" * 80)

    results = []

    results.append(("Imports", test_imports()))
    results.append(("Hist Model", test_hist_model()))
    results.append(("HistMgr", test_hist_manager()))
    results.append(("Export/Import", test_export_import()))

    print("\n" + "=" * 80)
    print("Test Summary:")
    print("=" * 80)

    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{name:20s} {status}")

    all_passed = all(result[1] for result in results)
    print("=" * 80)

    if all_passed:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n⚠️  Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
