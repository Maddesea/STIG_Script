# STIG Assessor Modularization - Developer Quick Start Guide

**Version:** 1.0
**Date:** 2025-11-16

---

## 🚀 Quick Start for Development Teams

### Prerequisites

1. Read `MODULARIZATION_SPEC.md` (full specification)
2. Review your team's assigned module(s) below
3. Set up development environment:
   ```bash
   cd /home/user/STIG_Script
   git checkout claude/modularize-for-parallel-dev-012hrduZvrxxwWsWvgZ7VimR
   python3 -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

---

## 👥 Team Assignments

### ✅ PREREQUISITE (Complete First - Sequential)

**TEAM 0 - Foundation Team**
- **Duration**: 2 days
- **Members**: 2 developers
- **Deliverables**:
  - Package structure (`stig_assessor/` directory tree)
  - `exceptions.py` (lines 276-299)
  - `core/constants.py` (lines 66-181)
  - All `__init__.py` files
- **Dependencies**: None
- **Start**: Immediately
- **Blocks**: All other teams

**Status**: 🔴 **MUST COMPLETE BEFORE OTHER TEAMS START**

---

### 🏃 PHASE 1 (Start After Team 0 Completes)

**TEAM 1 - Core Infrastructure**
- **Module**: `core/`
- **Files**: `state.py`, `deps.py`, `config.py`, `logging.py`
- **Lines**: 188-704
- **Duration**: 3 days
- **Dependencies**: constants.py, exceptions.py
- **Tests**: `tests/test_core/`
- **Critical Features**:
  - GlobalState singleton with signal handling
  - Config directory management (writable detection)
  - Rotating file logger
  - Dependency detection (tkinter, defusedxml)

**TEAM 2 - XML Foundation**
- **Module**: `xml/`
- **Files**: `schema.py`, `sanitizer.py`
- **Lines**: 705-1229
- **Duration**: 2 days
- **Dependencies**: constants.py
- **Tests**: `tests/test_xml/test_schema.py`, `tests/test_xml/test_sanitizer.py`
- **Critical Features**:
  - Namespace resolution
  - XML escaping (all dangerous characters)
  - IP/MAC validation
  - Status/severity normalization

**TEAM 3 - File Operations**
- **Module**: `io/`
- **Files**: `file_ops.py`
- **Lines**: 1230-1475
- **Duration**: 4 days
- **Dependencies**: core/*, exceptions.py
- **Tests**: `tests/test_io/`
- **Critical Features**:
  - Atomic writes with rollback
  - Encoding detection (fallback through list)
  - Symlink attack prevention
  - Backup creation

---

### 🏃 PHASE 2 (Start After Phase 1 Completes)

**TEAM 4 - XML Utilities**
- **Module**: `xml/`
- **Files**: `utils.py`
- **Lines**: 813-960
- **Duration**: 2 days
- **Dependencies**: xml/schema.py, xml/sanitizer.py
- **Tests**: `tests/test_xml/test_utils.py`
- **Critical Features**:
  - STIG_DATA extraction
  - Safe element text handling
  - VID extraction

**TEAM 5 - Validation**
- **Module**: `validation/`
- **Files**: `validator.py`
- **Lines**: 1932-2071
- **Duration**: 3 days
- **Dependencies**: xml/*, core/*
- **Tests**: `tests/test_validation/`
- **Critical Features**:
  - CKL structure validation
  - XCCDF validation
  - Error threshold checking
  - STIG Viewer 2.18 compliance

**TEAM 6 - History Management**
- **Module**: `history/`
- **Files**: `models.py`, `manager.py`
- **Lines**: 1476-1762
- **Duration**: 3 days
- **Dependencies**: core/*, xml/*
- **Tests**: `tests/test_history/`
- **Critical Features**:
  - Bisect insertion (maintain sort)
  - Content-based deduplication
  - XML serialization/parsing
  - Timezone-aware timestamps

**TEAM 7 - Boilerplate Templates**
- **Module**: `templates/`
- **Files**: `boilerplate.py`
- **Lines**: 1763-1931
- **Duration**: 2 days
- **Dependencies**: core/*, io/*
- **Tests**: `tests/test_templates/`
- **Critical Features**:
  - Template load/save (JSON)
  - VID + status lookup
  - Apply to VULN elements

**TEAM 8 - Remediation Models & Extractor**
- **Module**: `remediation/`
- **Files**: `models.py`, `extractor.py`
- **Lines**: 3304-3977
- **Duration**: 5 days
- **Dependencies**: core/*, xml/*, io/*
- **Tests**: `tests/test_remediation/`
- **Critical Features**:
  - Command extraction (regex patterns)
  - Multi-format export (JSON, CSV, Bash, PowerShell)
  - Dry-run script generation
  - Markdown code block parsing

**TEAM 9 - Evidence Management**
- **Module**: `evidence/`
- **Files**: `models.py`, `manager.py`
- **Lines**: 4292-4598
- **Duration**: 3 days
- **Dependencies**: core/*, io/*
- **Tests**: `tests/test_evidence/`
- **Critical Features**:
  - File import with deduplication (hash-based)
  - ZIP packaging
  - Metadata persistence
  - Export to directory

---

### 🏃 PHASE 3 (Start After Phase 2 Completes)

**TEAM 10 - Remediation Processor**
- **Module**: `remediation/`
- **Files**: `processor.py`
- **Lines**: 3978-4291
- **Duration**: 4 days
- **Dependencies**: remediation/*, xml/*, validation/*
- **Tests**: `tests/test_remediation/`
- **Critical Features**:
  - Bulk JSON import (array/object payloads)
  - CKL update logic
  - Deduplication by VID
  - Report generation

**TEAM 11 - Core Processor**
- **Module**: `processor/`
- **Files**: `processor.py`
- **Lines**: 2072-3303 (largest module!)
- **Duration**: 7 days
- **Dependencies**: ALL previous modules
- **Tests**: `tests/test_processor/`
- **Critical Features**:
  - XCCDF → CKL conversion
  - Merge with history preservation
  - Diff functionality
  - Repair mode
  - Statistics generation

---

### 🏃 PHASE 4 (Final Integration)

**TEAM 12 - User Interface**
- **Module**: `ui/`
- **Files**: `cli.py`, `gui.py`, `presets.py`
- **Lines**: 4599-5951
- **Duration**: 5 days
- **Dependencies**: ALL modules
- **Tests**: `tests/test_integration/`
- **Critical Features**:
  - CLI argument parsing
  - Command dispatch
  - GUI (tkinter)
  - Preset management
  - Async operations

**TEAM 13 - Testing & Documentation**
- **Duration**: Ongoing (parallel with all phases)
- **Deliverables**:
  - Unit tests for each module
  - Integration test suite
  - Performance benchmarks
  - Updated CLAUDE.md
  - API documentation
  - Migration guide

---

## 📋 Development Workflow

### 1. Claim Your Module

Each team should:
1. Review the specification for your assigned module(s)
2. Read the source code lines indicated
3. Identify all dependencies
4. Create a task breakdown

### 2. Create Branch

```bash
# Team leads create feature branch
git checkout -b team-N-module-name

# Example:
git checkout -b team-1-core-infrastructure
```

### 3. Module Development

**File Structure**:
```python
# stig_assessor/core/state.py
"""Global state management."""

from __future__ import annotations
from typing import Optional
import threading

# ... implementation ...
```

**Always Include**:
- Module docstring
- Type hints
- Error handling
- Logging (where appropriate)
- Thread safety documentation

### 4. Testing

**Test File Template**:
```python
# tests/test_core/test_state.py
"""Tests for GlobalState singleton."""

import unittest
from stig_assessor.core.state import GlobalState

class TestGlobalState(unittest.TestCase):
    def test_singleton(self):
        """Verify singleton behavior."""
        state1 = GlobalState()
        state2 = GlobalState()
        self.assertIs(state1, state2)

    # ... more tests ...
```

**Run Tests**:
```bash
python -m pytest tests/test_core/test_state.py -v
```

### 5. Code Review

**Checklist**:
- [ ] Type hints complete
- [ ] Docstrings present
- [ ] Error handling robust
- [ ] Tests pass (>80% coverage)
- [ ] No circular imports
- [ ] Thread safety documented
- [ ] Follows specification exactly

### 6. Integration

**Merge Process**:
1. Pass all unit tests
2. Pass integration tests (if applicable)
3. Code review approved
4. Merge to main branch

---

## 🔍 Common Pitfalls

### ❌ DON'T

```python
# Circular import
from stig_assessor.processor.processor import Proc  # In xml/utils.py - BAD!

# Missing error handling
def load_file(path):
    return open(path).read()  # No try/except - BAD!

# No type hints
def process(data):  # What type is data? - BAD!
    pass

# Direct import from old file
from STIG_Script import Cfg  # Old import - BAD!
```

### ✅ DO

```python
# Use absolute imports
from stig_assessor.core.config import CFG

# Proper error handling
from stig_assessor.exceptions import FileError

def load_file(path: Path) -> str:
    try:
        with path.open('r') as f:
            return f.read()
    except IOError as e:
        raise FileError(f"Failed to load {path}: {e}")

# Complete type hints
from typing import List, Optional

def process(data: List[str]) -> Optional[dict]:
    """Process data and return result."""
    # ...
```

---

## 🧪 Testing Requirements

### Unit Test Coverage

**Minimum**: 80% line coverage per module

**Required Tests**:
- Happy path (normal operation)
- Error cases (exceptions raised)
- Edge cases (empty input, None, max values)
- Thread safety (if applicable)

### Integration Tests

**Required Scenarios** (all teams collaborate):
1. Full XCCDF→CKL workflow
2. Merge workflow (3+ files)
3. Remediation end-to-end
4. Evidence lifecycle

### Performance Benchmarks

**Targets**:
- Large file (15K VULNs): <60 seconds
- Merge (100 files): <5 minutes
- Memory usage: <500MB peak

---

## 📚 Key Resources

### Documentation

- **Full Spec**: `MODULARIZATION_SPEC.md` (4379 lines)
- **Original Code**: `STIG_Script.py` (5951 lines)
- **Project Docs**: `CLAUDE.md` (current architecture)

### Code References

Use line numbers from spec to find code in `STIG_Script.py`:

```bash
# View specific lines
sed -n '188,275p' STIG_Script.py  # GlobalState class

# Search for class
grep -n "^class GlobalState" STIG_Script.py
```

### Communication

**Daily Standups**:
- What did you complete yesterday?
- What are you working on today?
- Any blockers?

**Blockers**:
- Dependency on another team's module?
- Unclear specification?
- Technical challenge?

Report immediately to unblock!

---

## 🎯 Success Criteria

### Module Complete When:

- [ ] All code extracted from original file
- [ ] All imports use new package structure
- [ ] Unit tests written (>80% coverage)
- [ ] All tests pass
- [ ] Code review approved
- [ ] Documentation updated
- [ ] No regression in functionality

### Phase Complete When:

- [ ] All modules in phase complete
- [ ] Integration tests pass
- [ ] Performance benchmarks met
- [ ] Next phase can start

---

## 📞 Support

**Questions?**

1. Check `MODULARIZATION_SPEC.md` first
2. Review original code in `STIG_Script.py`
3. Ask team lead
4. Escalate to project coordinator

**Found an issue in the spec?**

1. Document the issue
2. Propose a solution
3. Discuss with all teams
4. Update specification

---

## 🎓 Example: Extracting a Module

### Step-by-Step: Extract `core/state.py`

**1. Identify Code** (from spec: lines 188-275)

```bash
sed -n '188,275p' STIG_Script.py > temp_state.py
```

**2. Create Module File**

```python
# stig_assessor/core/state.py
"""Global state management and shutdown coordination."""

from __future__ import annotations
from typing import Optional, List, Callable, Set
from pathlib import Path
import threading
import signal
import atexit
import sys

# Copy GlobalState class from lines 188-275
# ... paste code here ...
```

**3. Update Imports**

Original:
```python
# Inside class methods
from STIG_Script import LOG
```

New:
```python
# At module top
from stig_assessor.core.logging import LOG  # Lazy import to avoid circular
```

**4. Create `__init__.py`**

```python
# stig_assessor/core/__init__.py
"""Core infrastructure modules."""

from stig_assessor.core.state import GlobalState, GLOBAL_STATE
from stig_assessor.core.config import Cfg, CFG
from stig_assessor.core.logging import Log, LOG
from stig_assessor.core.deps import Deps
from stig_assessor.core.constants import *

__all__ = [
    "GlobalState", "GLOBAL_STATE",
    "Cfg", "CFG",
    "Log", "LOG",
    "Deps",
]
```

**5. Write Tests**

```python
# tests/test_core/test_state.py
import unittest
from stig_assessor.core.state import GlobalState

class TestGlobalState(unittest.TestCase):
    def test_singleton(self):
        s1 = GlobalState()
        s2 = GlobalState()
        self.assertIs(s1, s2)

    def test_shutdown_flag(self):
        state = GlobalState()
        self.assertFalse(state.is_shutdown())
        state.shutdown()
        self.assertTrue(state.is_shutdown())

    # ... more tests ...
```

**6. Run Tests**

```bash
python -m pytest tests/test_core/test_state.py -v --cov=stig_assessor.core.state
```

**7. Integration**

Update code that uses GlobalState:

```python
# Old
from STIG_Script import GlobalState
GLOBAL = GlobalState()

# New
from stig_assessor.core.state import GLOBAL_STATE
# Use GLOBAL_STATE directly (module-level singleton)
```

---

## 🚦 Status Tracking

### Current Status

- [ ] Phase 0 (Foundation): Not started
- [ ] Phase 1: Not started
- [ ] Phase 2: Not started
- [ ] Phase 3: Not started
- [ ] Phase 4: Not started

Update this document as teams complete work!

---

**Good luck, teams! Let's build something great! 🚀**
