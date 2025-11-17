# STIG Assessor Test Suite

## Overview

This directory contains unit and integration tests for the STIG Assessor modular package.

## Test Structure

```
tests/
├── test_core/          # Core infrastructure tests (Team 1)
├── test_xml/           # XML processing tests (Teams 2, 4)
├── test_io/            # File operations tests (Team 3) ✅ COMPLETE
├── test_validation/    # Validation tests (Team 5)
├── test_history/       # History management tests (Team 6)
├── test_templates/     # Boilerplate tests (Team 7)
├── test_processor/     # Core processor tests (Team 11)
├── test_remediation/   # Remediation tests (Teams 8, 10)
├── test_evidence/      # Evidence management tests (Team 9)
└── test_integration/   # Integration tests (Team 13)
```

## Running Tests

### Run All Tests
```bash
python -m unittest discover -s tests -v
```

### Run Specific Module Tests
```bash
# Team 3 - File Operations
python -m unittest tests.test_io.test_file_ops -v
```

### Run with Coverage (if pytest-cov is available)
```bash
python -m pytest tests/ --cov=stig_assessor --cov-report=html
```

## Test Requirements

- **Coverage Target**: >80% line coverage per module
- **Test Types**: Unit tests, integration tests, edge cases
- **Error Handling**: All exception paths must be tested
- **Thread Safety**: Concurrent access tests where applicable

## Team 3 (File Operations) - Test Status ✅

**Module**: `stig_assessor/io/file_ops.py`
**Tests**: 25 tests, all passing
**Coverage**: Comprehensive coverage of:
- ✅ Retry decorator (3 tests)
- ✅ Atomic writes with rollback (6 tests)
- ✅ Encoding detection (5 tests)
- ✅ XML parsing with security checks (4 tests)
- ✅ ZIP archive creation (4 tests)
- ✅ Edge cases and error conditions (3 tests)

### Test Results
```
Ran 25 tests in 0.166s
OK
```

## Notes

- Tests use placeholder implementations for dependencies from Teams 1 and 2
- Once Teams 1 and 2 complete their work, replace placeholders with real implementations
- All tests maintain backward compatibility with air-gap requirements (no external dependencies)
