"""
STIG Assessor Test Suite

This package contains comprehensive tests for the STIG Assessor modular architecture.

Test Organization:
- test_core/ - Core infrastructure tests (state, config, logging, deps)
- test_xml/ - XML processing tests (schema, sanitizer, utils)
- test_io/ - File operations tests
- test_validation/ - Validation tests
- test_history/ - History management tests
- test_templates/ - Boilerplate template tests
- test_processor/ - Main processor tests
- test_remediation/ - Remediation tests (extractor, processor)
- test_evidence/ - Evidence management tests
- test_ui/ - User interface tests (CLI, GUI)
- test_integration/ - End-to-end integration tests
- test_performance/ - Performance benchmarks

Requirements:
- Python 3.9+
- pytest (for running tests)
- pytest-cov (for coverage reports)

Running Tests:
    # All tests
    python -m pytest tests/ -v

    # Specific module
    python -m pytest tests/test_core/ -v

    # With coverage
    python -m pytest tests/ -v --cov=stig_assessor --cov-report=html

    # Performance benchmarks
    python -m pytest tests/test_performance/ -v --benchmark-only

Coverage Target:
    Minimum 80% line coverage per module
"""

__version__ = "1.0.0"
__all__ = []
"""Test suite for STIG Assessor modular package."""
"""Test suite for STIG Assessor."""
