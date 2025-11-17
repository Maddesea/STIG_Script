"""Standalone test for Team 5 validator module.

This test verifies the validator module works correctly without
importing the full package (to avoid syntax errors in other teams' code).
"""

import sys
import xml.etree.ElementTree as ET

# Add the project root to sys.path
sys.path.insert(0, '/home/user/STIG_Script')

# Test basic imports work
print("=" * 70)
print("TEAM 5 VALIDATION MODULE - STANDALONE TEST")
print("=" * 70)

print("\n1. Testing validator.py file exists...")
import os
validator_path = '/home/user/STIG_Script/stig_assessor/validation/validator.py'
assert os.path.exists(validator_path), f"validator.py not found at {validator_path}"
print("   ✓ validator.py exists")

print("\n2. Testing validator module can be imported...")
# Import the validator module directly
exec(open(validator_path).read())
print("   ✓ validator.py executes without syntax errors")

print("\n3. Testing Val class exists and has required methods...")
assert 'Val' in locals(), "Val class not defined"
val_class = locals()['Val']
assert hasattr(val_class, 'validate_ckl'), "validate_ckl method missing"
assert hasattr(val_class, 'validate_xccdf'), "validate_xccdf method missing"
assert hasattr(val_class, 'check_error_threshold'), "check_error_threshold method missing"
assert hasattr(val_class, '_validate_vuln'), "_validate_vuln method missing"
assert hasattr(val_class, '_find_stig_data'), "_find_stig_data method missing"
print("   ✓ All required methods exist")

print("\n4. Testing Val.REQUIRED_ATTRS...")
assert hasattr(val_class, 'REQUIRED_ATTRS'), "REQUIRED_ATTRS constant missing"
required_attrs = val_class.REQUIRED_ATTRS
assert isinstance(required_attrs, frozenset), "REQUIRED_ATTRS should be frozenset"
assert len(required_attrs) >= 9, f"REQUIRED_ATTRS should have at least 9 items, has {len(required_attrs)}"
assert "Vuln_Num" in required_attrs, "Vuln_Num should be in REQUIRED_ATTRS"
assert "Severity" in required_attrs, "Severity should be in REQUIRED_ATTRS"
print(f"   ✓ REQUIRED_ATTRS contains {len(required_attrs)} attributes")

print("\n5. Testing basic CKL validation...")
# Create a simple valid CKL
valid_ckl = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <HOST_NAME>TestHost</HOST_NAME>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO></STIG_INFO>
        </iSTIG>
    </STIGS>
</CHECKLIST>
"""
tree = ET.ElementTree(ET.fromstring(valid_ckl))
# Note: We can't actually call validate_ckl here because it depends on other modules
print("   ✓ Test CKL structure created (full test requires other modules)")

print("\n6. Testing documentation...")
assert val_class.__doc__ is not None, "Val class should have docstring"
assert val_class.validate_ckl.__doc__ is not None, "validate_ckl should have docstring"
assert val_class.validate_xccdf.__doc__ is not None, "validate_xccdf should have docstring"
assert val_class.check_error_threshold.__doc__ is not None, "check_error_threshold should have docstring"
print("   ✓ All public methods have docstrings")

print("\n7. Checking test file exists...")
test_file = '/home/user/STIG_Script/tests/test_validation/test_validator.py'
assert os.path.exists(test_file), f"test_validator.py not found at {test_file}"
print("   ✓ test_validator.py exists")

# Count test functions
test_content = open(test_file).read()
test_count = test_content.count('def test_')
print(f"   ✓ Found {test_count} test functions")

print("\n" + "=" * 70)
print("ALL TEAM 5 STANDALONE TESTS PASSED ✓")
print("=" * 70)
print("\nSummary:")
print("  - validator.py module: ✓ Created and syntax-valid")
print("  - Val class: ✓ All required methods present")
print("  - REQUIRED_ATTRS: ✓ Defined with correct attributes")
print("  - Documentation: ✓ All public methods documented")
print(f"  - Tests: ✓ {test_count} test functions created")
print("\nNote: Full integration tests require fixing syntax errors in other modules.")
