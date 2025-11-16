# STIG Assessor Test Suite

**Version:** 1.0
**Date:** 2025-11-16
**Coverage Target:** 80% minimum per module

---

## Overview

Comprehensive test suite for the STIG Assessor modular architecture, covering:
- **Unit tests** for individual modules
- **Integration tests** for end-to-end workflows
- **Performance benchmarks** for ensuring no regression
- **GUI tests** for user interface components

---

## Quick Start

### Installation

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-benchmark memory-profiler

# Or install all development dependencies
pip install -r requirements-dev.txt
```

### Run All Tests

```bash
# Run complete test suite
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ -v --cov=stig_assessor --cov-report=html

# Open coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

---

## Test Organization

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Shared fixtures and utilities
├── README.md                   # This file
│
├── test_core/                  # Core infrastructure tests (TEAM 1)
│   ├── test_state.py           # GlobalState singleton tests
│   ├── test_config.py          # Cfg configuration tests
│   ├── test_logging.py         # Log logger tests
│   └── test_deps.py            # Deps dependency detection tests
│
├── test_xml/                   # XML processing tests (TEAMS 2, 4)
│   ├── test_schema.py          # Sch schema tests
│   ├── test_sanitizer.py       # San sanitizer tests
│   └── test_utils.py           # XML utility tests
│
├── test_io/                    # File operations tests (TEAM 3)
│   └── test_file_ops.py        # FO atomic writes, backups, encoding
│
├── test_validation/            # Validation tests (TEAM 5)
│   └── test_validator.py       # Val STIG Viewer compliance tests
│
├── test_history/               # History management tests (TEAM 6)
│   ├── test_models.py          # Hist dataclass tests
│   └── test_manager.py         # HistMgr lifecycle tests
│
├── test_templates/             # Boilerplate tests (TEAM 7)
│   └── test_boilerplate.py     # BP template management tests
│
├── test_processor/             # Main processor tests (TEAM 11)
│   └── test_processor.py       # Proc XCCDF→CKL, merge, diff tests
│
├── test_remediation/           # Remediation tests (TEAMS 8, 10)
│   ├── test_models.py          # Fix dataclass tests
│   ├── test_extractor.py       # FixExt extraction tests
│   └── test_processor.py       # FixResPro import tests
│
├── test_evidence/              # Evidence management tests (TEAM 9)
│   ├── test_models.py          # EvidenceMeta dataclass tests
│   └── test_manager.py         # EvidenceMgr lifecycle tests
│
├── test_ui/                    # User interface tests (TEAM 12)
│   ├── test_cli.py             # CLI argument parsing tests
│   ├── test_gui.py             # GUI tests (requires tkinter)
│   └── test_presets.py         # Preset management tests
│
├── test_integration/           # Integration tests (TEAM 13)
│   └── test_workflows.py       # End-to-end workflow tests
│
└── test_performance/           # Performance benchmarks (TEAM 13)
    └── test_benchmarks.py      # Performance and memory tests
```

---

## Running Specific Tests

### By Module

```bash
# Test specific module
python -m pytest tests/test_core/ -v
python -m pytest tests/test_xml/ -v
python -m pytest tests/test_remediation/ -v

# Test specific file
python -m pytest tests/test_core/test_state.py -v

# Test specific test
python -m pytest tests/test_core/test_state.py::TestGlobalState::test_singleton_pattern -v
```

### By Category (Markers)

```bash
# Run only integration tests
python -m pytest tests/ -v -m integration

# Run only performance benchmarks
python -m pytest tests/ -v -m performance --benchmark-only

# Skip slow tests
python -m pytest tests/ -v -m "not slow"

# Run GUI tests (requires tkinter)
python -m pytest tests/ -v -m gui
```

Available markers:
- `integration` - Integration tests (end-to-end workflows)
- `performance` - Performance benchmarks
- `slow` - Slow-running tests
- `gui` - Tests requiring GUI/tkinter

---

## Coverage Reports

### Generate HTML Coverage Report

```bash
python -m pytest tests/ --cov=stig_assessor --cov-report=html
open htmlcov/index.html
```

### Generate Terminal Coverage Report

```bash
python -m pytest tests/ --cov=stig_assessor --cov-report=term-missing
```

### Coverage Requirements

Minimum coverage per module: **80%**

Check coverage for specific module:

```bash
python -m pytest tests/test_core/ --cov=stig_assessor.core --cov-report=term-missing
```

---

## Performance Benchmarks

### Run Benchmarks

```bash
# Run all benchmarks
python -m pytest tests/test_performance/ -v --benchmark-only

# Run with comparison
python -m pytest tests/test_performance/ --benchmark-autosave

# Compare to saved baseline
python -m pytest tests/test_performance/ --benchmark-compare=0001
```

### Performance Targets

| Benchmark | Target | Current |
|-----------|--------|---------|
| Load 15K VULNs | < 30s | TBD |
| Process 15K VULNs | < 60s | TBD |
| Merge 10 files | < 30s | TBD |
| Merge 100 files | < 5min | TBD |
| Import 1000 results | < 30s | TBD |
| Peak memory (15K) | < 500MB | TBD |

---

## Writing Tests

### Test Template

```python
"""
Tests for [module name].

Tests cover:
- [Feature 1]
- [Feature 2]
- [Feature 3]
"""

import unittest
from pathlib import Path


class TestModuleName(unittest.TestCase):
    """Test suite for [ClassName]."""

    def setUp(self):
        """Set up test fixtures."""
        # Initialize test data
        pass

    def tearDown(self):
        """Clean up test artifacts."""
        # Clean up temporary files
        pass

    def test_specific_feature(self):
        """Test [specific feature].

        Requirements:
        - [Requirement 1]
        - [Requirement 2]
        """
        # Arrange
        # ... set up test data ...

        # Act
        # ... execute test ...

        # Assert
        # self.assertEqual(actual, expected)
        pass


if __name__ == '__main__':
    unittest.main()
```

### Using Fixtures

```python
def test_with_temp_directory(temp_dir):
    """Test using temporary directory fixture."""
    # temp_dir is a Path object to temporary directory
    test_file = temp_dir / "test.txt"
    test_file.write_text("content")
    assert test_file.exists()
    # Automatically cleaned up after test


def test_with_sample_xccdf(sample_xccdf_file):
    """Test using sample XCCDF file."""
    # sample_xccdf_file is a Path to temporary XCCDF file
    assert sample_xccdf_file.exists()
    content = sample_xccdf_file.read_text()
    assert "Benchmark" in content
```

### Testing Exceptions

```python
from stig_assessor.exceptions import ValidationError

def test_validation_error_raised():
    """Test that validation error is raised for invalid input."""
    with self.assertRaises(ValidationError) as ctx:
        Val.validate_ckl(invalid_file_path)

    # Optionally check error message
    self.assertIn("Invalid CKL", str(ctx.exception))
```

---

## Shared Fixtures

Available in `conftest.py`:

### Directory Fixtures

- `temp_dir` - Temporary directory (auto-cleanup)

### File Content Fixtures

- `sample_xccdf_content` - Valid XCCDF XML string
- `sample_ckl_content` - Valid CKL XML string
- `sample_remediation_json` - Remediation results JSON

### File Fixtures

- `sample_xccdf_file` - Temporary XCCDF file
- `sample_ckl_file` - Temporary CKL file

### Mock Fixtures

- `mock_logger` - Mock logger for testing log output

### Utility Functions

- `create_test_ckl(temp_dir, num_vulns)` - Create test CKL with N VULNs
- `assert_valid_ckl_structure(ckl_path)` - Validate CKL structure

---

## Integration Tests

Integration tests verify end-to-end workflows:

### Test Workflows

1. **XCCDF to CKL Workflow**
   - Load XCCDF benchmark
   - Convert to CKL
   - Apply boilerplate templates
   - Validate output

2. **Merge Workflow**
   - Create base checklist
   - Create history checklists
   - Merge with history preservation
   - Verify deduplication

3. **Remediation Workflow**
   - Extract fixes from XCCDF
   - Generate remediation scripts
   - Import results to CKL
   - Verify status updates

4. **Evidence Workflow**
   - Import evidence files
   - Export evidence
   - Package to ZIP
   - Verify integrity

### Running Integration Tests

```bash
# Run all integration tests
python -m pytest tests/test_integration/ -v -m integration

# Run specific workflow
python -m pytest tests/test_integration/test_workflows.py::TestXCCDFtoCKLWorkflow -v
```

---

## Test-Driven Development (TDD)

Recommended workflow for new features:

### 1. Write Test First

```python
def test_new_feature():
    """Test new feature behavior."""
    # This test will fail initially
    result = new_feature_function()
    assert result == expected_value
```

### 2. Run Test (Should Fail)

```bash
python -m pytest tests/test_module/test_file.py::test_new_feature -v
# Expected: FAILED (feature not implemented yet)
```

### 3. Implement Feature

```python
def new_feature_function():
    # Implement feature
    return expected_value
```

### 4. Run Test Again (Should Pass)

```bash
python -m pytest tests/test_module/test_file.py::test_new_feature -v
# Expected: PASSED
```

### 5. Refactor and Verify

```bash
# Ensure all tests still pass after refactoring
python -m pytest tests/ -v
```

---

## Continuous Integration

### Pre-Commit Checks

Before committing code:

```bash
# Run all tests
python -m pytest tests/ -v

# Check coverage
python -m pytest tests/ --cov=stig_assessor --cov-fail-under=80

# Run linting (if configured)
# flake8 stig_assessor/
# pylint stig_assessor/
```

### CI Pipeline

Recommended CI pipeline (GitHub Actions, GitLab CI, etc.):

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11]

    steps:
    - uses: actions/checkout@v2

    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        pip install -e .
        pip install pytest pytest-cov pytest-benchmark

    - name: Run tests
      run: |
        python -m pytest tests/ -v --cov=stig_assessor --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v2
```

---

## Troubleshooting

### Tests Fail Due to Missing Dependencies

```bash
# Install all test dependencies
pip install pytest pytest-cov pytest-benchmark memory-profiler

# Or use requirements file
pip install -r requirements-dev.txt
```

### ImportError: No module named 'stig_assessor'

```bash
# Ensure package is in Python path
export PYTHONPATH=/path/to/STIG_Script:$PYTHONPATH

# Or install in development mode
pip install -e .
```

### GUI Tests Fail

```bash
# GUI tests require tkinter
# Ubuntu/Debian:
sudo apt-get install python3-tk

# RHEL/CentOS:
sudo yum install python3-tkinter

# Skip GUI tests if not needed:
python -m pytest tests/ -v -m "not gui"
```

### Slow Test Execution

```bash
# Run only fast tests
python -m pytest tests/ -v -m "not slow"

# Run tests in parallel (requires pytest-xdist)
pip install pytest-xdist
python -m pytest tests/ -v -n auto
```

---

## Test Coverage Goals

### Phase 1 (Foundation) - Target: 85%
- Core infrastructure
- XML processing
- File operations

### Phase 2 (Business Logic) - Target: 80%
- Validation
- History management
- Templates
- Remediation extraction
- Evidence management

### Phase 3 (Integration) - Target: 80%
- Main processor
- Remediation processor

### Phase 4 (UI) - Target: 70%
- CLI (easier to test)
- GUI (harder to test, lower target acceptable)

---

## Contributing

### Adding New Tests

1. **Identify module** to test
2. **Create test file** in appropriate directory
3. **Write comprehensive tests** covering:
   - Happy path (normal operation)
   - Error cases (exceptions)
   - Edge cases (boundary conditions)
   - Thread safety (if applicable)
4. **Run tests** and verify they pass
5. **Check coverage** meets minimum 80%
6. **Submit PR** with tests

### Test Naming Conventions

```python
# Class names: TestClassName
class TestGlobalState(unittest.TestCase):
    pass

# Method names: test_what_it_tests
def test_singleton_pattern(self):
    pass

# Descriptive names for clarity
def test_merge_deduplicates_identical_history_entries(self):
    pass
```

---

## Resources

### Documentation

- **Project Docs**: `CLAUDE.md`
- **API Docs**: `API_DOCUMENTATION.md`
- **Migration Guide**: `MIGRATION_GUIDE.md`
- **Dev Guide**: `DEV_QUICK_START.md`

### Testing Frameworks

- **pytest**: https://docs.pytest.org/
- **unittest**: https://docs.python.org/3/library/unittest.html
- **pytest-cov**: https://pytest-cov.readthedocs.io/
- **pytest-benchmark**: https://pytest-benchmark.readthedocs.io/

---

## Contact

- **Issues**: https://github.com/Maddesea/STIG_Script/issues
- **Discussions**: https://github.com/Maddesea/STIG_Script/discussions

---

**Maintained By:** TEAM 13 (Testing & Documentation)
**Last Updated:** 2025-11-16
