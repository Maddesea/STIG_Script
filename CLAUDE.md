# CLAUDE.md - STIG Assessor Complete

## Project Overview

**STIG Assessor Complete** is a production-ready, zero-dependency, air-gap certified security compliance tool for Department of Defense (DoD) Security Technical Implementation Guide (STIG) assessments.

- **Version:** 7.4.3
- **Build Date:** 2026-01-02
- **STIG Viewer Compatibility:** 2.18
- **Language:** Python 3.9+
- **Lines of Code:** ~6,776 (monolith) + ~6,600 (modular package)
- **Architecture:** Dual - Single-file monolith for air-gap + modular package for development

### Core Capabilities

1. **XCCDF → CKL Conversion** - Convert STIG benchmarks to checklist format
2. **Checklist Merging** - Merge multiple checklists with history preservation
3. **Fix Extraction** - Extract remediation commands to JSON/CSV/Bash/PowerShell
4. **Bulk Remediation** - Import remediation results (supports 300+ checks at once)
5. **Evidence Management** - Import, export, and package evidence files
6. **History Tracking** - Microsecond-precision change tracking with deduplication
7. **Boilerplate Templates** - Status-aware compliance text templates
8. **GUI & CLI** - Full feature parity between interfaces

---

## File Structure

```
STIG_Script/
├── STIG_Script.py              # Single comprehensive script (~6,776 lines)
├── CLAUDE.md                   # This file - AI assistant documentation
├── requirements-dev.txt        # Development/test dependencies
├── .github/workflows/          # CI/CD automation
│   └── ci.yml                  # GitHub Actions workflow
├── stig_assessor/              # Modular package (~6,600 lines)
│   ├── core/                   # Foundation modules
│   │   ├── constants.py        # Enums, limits, platform detection
│   │   ├── state.py            # GlobalState singleton
│   │   ├── config.py           # Configuration & directory management
│   │   ├── logging.py          # Rotating file logger
│   │   └── deps.py             # Dependency detection
│   ├── exceptions.py           # Exception hierarchy
│   ├── xml/                    # XML processing
│   │   ├── schema.py           # Namespaces & schema definitions
│   │   ├── sanitizer.py        # Input sanitization
│   │   └── utils.py            # XML utilities
│   ├── io/                     # File operations
│   │   └── file_ops.py         # Atomic writes, encoding detection
│   ├── validation/             # STIG Viewer validation
│   │   └── validator.py        # CKL validation (Team 5)
│   ├── history/                # History tracking
│   │   ├── models.py           # History dataclass
│   │   └── manager.py          # History lifecycle management
│   ├── templates/              # Boilerplate management
│   │   └── boilerplate.py      # Template system
│   ├── remediation/            # Remediation extraction/import
│   │   ├── models.py           # Fix dataclasses
│   │   ├── extractor.py        # Command extraction
│   │   └── processor.py        # Bulk import processing
│   ├── evidence/               # Evidence management
│   │   ├── models.py           # Evidence metadata
│   │   └── manager.py          # Evidence lifecycle
│   └── ui/                     # User interfaces
│       ├── cli.py              # CLI entry point
│       ├── gui.py              # Tkinter GUI
│       └── presets.py          # GUI preset management
├── tests/                      # Test suite (~4,500 lines)
│   ├── conftest.py             # Shared fixtures
│   ├── test_core/              # Core infrastructure tests
│   ├── test_xml/               # XML processing tests
│   ├── test_io/                # File operations tests
│   ├── test_validation/        # Validation tests
│   ├── test_history/           # History tracking tests
│   ├── test_templates/         # Boilerplate tests
│   ├── test_remediation/       # Remediation tests
│   ├── test_evidence/          # Evidence tests
│   └── test_integration/       # End-to-end tests
└── .git/                       # Git repository

Runtime directories (created in ~/.stig_assessor/):
├── logs/                   # Application logs (rotating, 10MB max)
├── backups/                # Automatic CKL backups (.bak files)
├── evidence/               # Evidence file storage (organized by VID)
├── templates/              # Boilerplate templates (boilerplate.json)
├── presets/                # Saved configuration presets
├── fixes/                  # Extracted remediation scripts
└── exports/                # Export outputs
```

---

## Architecture Overview

### Core Classes (26 total in monolith)

#### Constants & Enums
- **`Status`** (line 202) - STIG status values enum
- **`Severity`** (line 220) - STIG severity levels enum

#### Foundation Layer
- **`GlobalState`** (line 242) - Process-wide shutdown coordination
- **`Cfg`** (line 547) - Application configuration, directory management
- **`Log`** (line 720) - Thread-safe logging with contextual metadata
- **`Deps`** (line 450) - Dependency detection (tkinter, XML parser)

#### Error Handling
- **`STIGError`** (line 362) - Base exception class
- **`ValidationError`** (line 377) - STIG Viewer compatibility errors
- **`FileError`** (line 381) - File I/O errors
- **`ParseError`** (line 385) - XML parsing errors

#### XML & Validation
- **`Sch`** (line 866) - XML schema definitions (namespaces, elements)
- **`XmlUtils`** (line 974) - XML utilities
- **`San`** (line 1215) - XML sanitization (prevents injection attacks)
- **`Val`** (line 2531) - STIG Viewer 2.18 compatibility validation

#### Core Operations
- **`FO`** (line 1579) - File operations (atomic writes, backups, encoding detection)
- **`Proc`** (line 2702) - Main processor for XCCDF→CKL, merge operations
- **`BP`** (line 2303) - Boilerplate template management

#### History & Evidence
- **`Hist`** (line 1892) - Individual history entry (dataclass)
- **`HistMgr`** (line 1955) - History lifecycle management (deduplication, sorting)
- **`EvidenceMeta`** (line 4915) - Evidence metadata (dataclass)
- **`EvidenceMgr`** (line 4961) - Evidence import/export/packaging

#### Remediation System
- **`Fix`** (line 3938) - Single remediation fix (dataclass)
- **`FixExt`** (line 3969) - Fix extraction from XCCDF (multi-format export)
- **`FixResult`** (line 4606) - Remediation execution result (dataclass)
- **`FixResPro`** (line 4646) - Remediation results processor (bulk import)

#### User Interface
- **`PresetMgr`** (line 5231) - GUI preset management
- **`GUI`** (lines 5300+) - Tkinter-based graphical interface (async operations)

---

## Key Workflows

### 1. Create CKL from XCCDF
```bash
python STIG_Script.py --create \
  --xccdf /path/to/benchmark.xml \
  --asset "SERVER-01" \
  --out /path/to/output.ckl \
  --ip 192.168.1.100 \
  --mac 00:11:22:33:44:55 \
  --role "Member Server" \
  --marking "CUI" \
  --apply-boilerplate
```

**Code Path:** `main()` → `Proc.xccdf_to_ckl()` → `Proc._process_xccdf()` → `FO.save_xml()`

### 2. Merge Checklists
```bash
python STIG_Script.py --merge \
  --base current.ckl \
  --histories old1.ckl old2.ckl old3.ckl \
  --merge-out merged.ckl
```

**Code Path:** `main()` → `Proc.merge()` → `HistMgr.merge()` → `FO.save_xml()`

### 3. Extract Fixes
```bash
python STIG_Script.py --extract benchmark.xml \
  --outdir ./fixes \
  --script-dry-run  # Optional: generates dry-run scripts
```

**Code Path:** `main()` → `FixExt()` → `FixExt.extract()` → `FixExt.to_*()` methods

**Outputs:** `fixes.json`, `fixes.csv`, `remediate.sh`, `Remediate.ps1`

### 4. Apply Remediation Results
```bash
python STIG_Script.py --apply-results results.json \
  --checklist current.ckl \
  --results-out updated.ckl
```

**Code Path:** `main()` → `FixResPro.load()` → `FixResPro.update_ckl()`

### 5. Evidence Management
```bash
# Import evidence
python STIG_Script.py --import-evidence V-123456 /path/to/screenshot.png \
  --evidence-desc "System configuration screenshot" \
  --evidence-cat "config"

# Export all evidence
python STIG_Script.py --export-evidence /path/to/output_dir

# Package evidence
python STIG_Script.py --package-evidence evidence_package.zip
```

---

## Development Guidelines

### Code Style Conventions

1. **Type Hints:** Always use type annotations (PEP 484/585)
   ```python
   def process(self, data: Dict[str, Any]) -> Optional[str]:
   ```

2. **Docstrings:** Classes have docstrings; methods use inline comments
   ```python
   class Example:
       """Brief description of class purpose."""
   ```

3. **Error Handling:** Use custom exceptions (`STIGError` hierarchy)
   ```python
   raise ValidationError(f"Invalid status: {status}")
   ```

4. **Logging:** Use structured logging with context
   ```python
   LOG.info(f"Processing {len(vulns)} vulnerabilities")
   LOG.debug(f"Details: {details}")
   ```

5. **Thread Safety:** Use locks for shared state
   ```python
   with self._lock:
       # Critical section
   ```

### XML Processing Rules

1. **Namespace Handling:** Always use `Sch.ns()` for namespace resolution
   ```python
   finding = elem.find(".//VULN", Sch.NS)
   ```

2. **Sanitization:** All user input MUST pass through `San.txt()` or `San.xml_safe()`
   ```python
   elem.text = San.txt(user_input)
   ```

3. **Atomic Writes:** Always use `FO.atomic_write()` for XML files
   ```python
   FO.atomic_write(path, content, backup=True)
   ```

4. **Encoding Detection:** Use `FO.read_with_fallback()` for robust file reading
   ```python
   content = FO.read_with_fallback(path)
   ```

### Performance Considerations

- **Large Files:** Files >50MB trigger chunked processing (`LARGE_FILE_THRESHOLD`)
- **Memory Management:** Explicit `gc.collect()` after processing large datasets
- **Retry Logic:** Network/IO operations use exponential backoff (decorator `@retry`)
- **Streaming:** Use generators for large vulnerability lists

---

## Configuration System

### Environment Variables
- **`USERPROFILE`** / **`HOME`** - User home directory detection
- No other environment dependencies (air-gap compatible)

### Directory Initialization
Order of preference for `~/.stig_assessor/`:
1. `Path.home()`
2. `$USERPROFILE` or `$HOME`
3. `$TMPDIR/stig_user`
4. `$CWD/.stig_home`

### Limits & Thresholds
```python
MAX_FILE = 500 MB          # Maximum file size
MAX_HIST = 200             # Maximum history entries per vulnerability
MAX_FIND = 65,000 chars    # Maximum finding details length
MAX_COMM = 32,000 chars    # Maximum comments length
MAX_MERGE = 100            # Maximum checklists to merge
MAX_VULNS = 15,000         # Maximum vulnerabilities per checklist
KEEP_BACKUPS = 30          # Backup retention count
KEEP_LOGS = 15             # Log retention count
```

---

## Testing & Validation

### STIG Viewer Compatibility
The tool validates against STIG Viewer 2.18 schema:
- CKL XML structure (`Val.validate_ckl()`)
- Required elements: `ASSET`, `STIGS`, `iSTIG`, `STIG_INFO`, `VULN`
- Status values: `NotAFinding`, `Open`, `Not_Applicable`, `Not_Reviewed`
- Severity codes: `high`, `medium`, `low`

### Manual Testing Checklist
When modifying core functionality:
1. Test XCCDF→CKL conversion with sample STIG
2. Verify checklist merge preserves all history
3. Validate fix extraction generates valid scripts
4. Test remediation import with bulk JSON (100+ results)
5. Verify evidence import/export/package workflow
6. Test GUI async operations (no UI freezing)
7. Run validation on output CKL files

### Common Edge Cases
- **Empty/null values** - Handle with `San.txt()` defaults
- **Unicode characters** - Use UTF-8 encoding everywhere
- **Large comments** - Truncate with `San.trunc()`
- **Missing XCCDF elements** - Provide sensible defaults
- **Corrupted CKL files** - Graceful error messages

---

## Common Tasks for AI Assistants

### Adding a New CLI Command

1. Add argument group in `main()` (line ~4494+)
   ```python
   new_group = parser.add_argument_group("New Feature")
   new_group.add_argument("--new-feature", help="Description")
   ```

2. Add processing logic in `main()` (line ~4550+)
   ```python
   if args.new_feature:
       result = proc.new_feature_method(args.new_feature)
       print(json.dumps(result, indent=2))
       return 0
   ```

3. Implement method in `Proc` class (line ~1536+)

### Adding a New Boilerplate Template

Edit default boilerplate in `ensure_default_boilerplates()` (line 4467):
```python
"V-123456": {
    "NotAFinding": "Template text for Not a Finding",
    "Open": "Template text for Open findings"
}
```

### Modifying XML Structure

1. Update `Sch` class (line 555) if new namespaces/elements
2. Update `Val.validate_ckl()` (line ~1431) for new validation rules
3. Use `San.txt()` for all user-controlled content

### Adding Evidence Categories

Modify `EvidenceMgr` (line 3244) - categories are freeform strings:
```python
evidence_mgr.import_file(vid, path, category="new_category")
```

### Extending Fix Extraction

Add new patterns in `FixExt._extract_commands()` (line ~2300+):
```python
# Add regex pattern for new command format
pattern = re.compile(r'new_pattern', re.MULTILINE)
```

---

## Debugging Guide

### Enable Verbose Logging
```bash
python STIG_Script.py --verbose [command]
```
Logs written to: `~/.stig_assessor/logs/stig_assessor.log`

### Common Issues

**"Cannot find writable home directory"**
- Solution: Check permissions on `$HOME`, `$USERPROFILE`, or `/tmp`

**"XML parser failed"**
- Solution: Verify Python installation includes `xml.etree.ElementTree`

**"Invalid CKL structure"**
- Solution: Run `--validate` to identify schema violations

**"tkinter not available"**
- Solution: Install `python3-tk` package (GUI only)

### Stack Traces
All exceptions include:
- Operation context (which file, which vulnerability)
- Rollback information (backup file location)
- Recovery suggestions

---

## Security Considerations

### XML Injection Prevention
- All user input sanitized via `San.txt()` (line 663)
- Regex-based scrubbing of dangerous characters: `<`, `>`, `&`, `'`, `"`
- Size limits enforced (`MAX_FIND`, `MAX_COMM`)

### File System Security
- Atomic writes with rollback (no partial files)
- Backup creation before modifications
- Path traversal prevention (not explicitly shown, but paths normalized)

### Air-Gap Compliance
- **Zero external dependencies** (stdlib only)
- **No network calls** (fully offline)
- **No telemetry** (no data collection)

---

## GUI Architecture (Optional Component)

### Async Design Pattern
```python
class GUI:
    def _run_async(self, func, callback):
        """Run operation in background thread, call callback on completion."""
        threading.Thread(target=self._worker, args=(func, callback)).start()
```

### Features
- **Preset Management** - Save/load common configurations
- **Progress Bars** - Visual feedback for long operations
- **Status Messages** - Real-time operation updates
- **Non-blocking** - UI remains responsive during processing

---

## Modularization & Testing Infrastructure

### Modularization Status

The STIG Assessor codebase is transitioning from a monolithic single-file architecture to a modular package structure to enable parallel development by multiple teams.

**Current Status:** ✅ Specification Complete - Implementation Ready

**Key Documents:**
- **`MODULARIZATION_SPEC.md`** (4,379 lines) - Complete technical specification for modular architecture
- **`MODULARIZATION_SUMMARY.md`** - Executive summary and project overview
- **`DEV_QUICK_START.md`** - Developer onboarding guide with team assignments
- **`MIGRATION_GUIDE.md`** - User migration guide from monolithic to modular
- **`API_DOCUMENTATION.md`** - Comprehensive API reference for all modules

### Target Modular Structure

```
stig_assessor/                    # Main package
├── core/                         # Foundation (state, config, logging, deps)
├── exceptions.py                 # All error classes
├── xml/                          # XML processing (schema, sanitizer, utils)
├── io/                           # File operations (atomic writes, backups)
├── validation/                   # STIG Viewer compliance validation
├── history/                      # History tracking and management
├── templates/                    # Boilerplate template management
├── processor/                    # Main XCCDF→CKL processor
├── remediation/                  # Remediation extraction and import
├── evidence/                     # Evidence file management
└── ui/                           # User interfaces (CLI, GUI)
```

**Total:** 25+ focused modules, ~240 lines per file average

### Development Team Assignments

- **TEAM 0**: Foundation (constants, exceptions) - 2 days
- **TEAM 1**: Core infrastructure - 3 days
- **TEAM 2**: XML foundation - 2 days
- **TEAM 3**: File operations - 4 days
- **TEAM 4**: XML utilities - 2 days
- **TEAM 5**: Validation - 3 days
- **TEAM 6**: History management - 3 days
- **TEAM 7**: Boilerplate templates - 2 days
- **TEAM 8**: Remediation extractor - 5 days
- **TEAM 9**: Evidence management - 3 days
- **TEAM 10**: Remediation processor - 4 days
- **TEAM 11**: Core processor - 7 days
- **TEAM 12**: User interfaces - 5 days
- **TEAM 13**: Testing & documentation - Ongoing

**Timeline:** ~23 days elapsed time with full parallelization (vs. ~70 days sequential)

### Testing Infrastructure (Team 13 Deliverables)

**Comprehensive Test Suite:** `tests/` directory

```
tests/
├── conftest.py                  # Shared fixtures and utilities
├── test_core/                   # Core infrastructure tests
├── test_xml/                    # XML processing tests
├── test_io/                     # File operations tests
├── test_validation/             # Validation tests
├── test_history/                # History management tests
├── test_templates/              # Boilerplate tests
├── test_processor/              # Main processor tests
├── test_remediation/            # Remediation tests
├── test_evidence/               # Evidence management tests
├── test_ui/                     # User interface tests
├── test_integration/            # End-to-end workflow tests
└── test_performance/            # Performance benchmarks
```

**Test Coverage Target:** Minimum 80% line coverage per module

**Running Tests:**
```bash
# All tests with coverage
python -m pytest tests/ -v --cov=stig_assessor --cov-report=html

# Specific module
python -m pytest tests/test_core/ -v

# Integration tests
python -m pytest tests/test_integration/ -v -m integration

# Performance benchmarks
python -m pytest tests/test_performance/ -v --benchmark-only
```

**Performance Benchmarks:**
- Load 15K VULNs: < 30 seconds
- Process 15K VULNs: < 60 seconds
- Merge 100 files: < 5 minutes
- Import 1000 remediation results: < 30 seconds
- Peak memory usage: < 500MB

### Backward Compatibility

**100% Backward Compatible** - All existing scripts continue to work:

```bash
# Old way (still works)
python STIG_Script.py --create --xccdf benchmark.xml --out output.ckl

# New way (when modular version is deployed)
python -m stig_assessor.cli --create --xccdf benchmark.xml --out output.ckl
```

### Migration Resources

- **`MIGRATION_GUIDE.md`** - Step-by-step migration instructions
- **`API_DOCUMENTATION.md`** - Complete API reference
- **`tests/README.md`** - Test suite documentation

### Benefits of Modularization

1. **Parallel Development** - 13 teams can work independently (70% faster)
2. **Better Testability** - Isolated unit tests for each component
3. **Easier Maintenance** - Smaller files (~240 lines vs. 6000)
4. **Code Reusability** - Modules can be imported independently
5. **Clear Responsibilities** - Each module has one focused purpose

### Air-Gap Compatibility

**Maintained** - The modular version will support:
- Single-file distribution option (via build script)
- Zero external dependencies (stdlib only)
- Full offline operation

---

## Git Workflow

### Branch Strategy
- **Current Branch:** `claude/team-13-tasks-01RcfGasxbQcR5LpvYK68XeX` (Team 13 - Testing & Documentation)
- **Previous Branches:**
  - `claude/claude-md-mi10q1bblig17kze-01JwjQkipWiaNFzRzEYubSgs`
  - `claude/modularize-for-parallel-dev-012hrduZvrxxwWsWvgZ7VimR`
- All changes MUST be committed to the assigned branch
- Push with: `git push -u origin <branch-name>`

### Commit Message Style
Based on repository history:
- Imperative mood: "Create STIG_Script.py" (not "Created")
- Descriptive: Explain WHAT changed
- Concise: 1-2 lines preferred

### Before Committing
1. Test basic workflows (create, merge, extract, apply)
2. Verify no syntax errors: `python STIG_Script.py --version`
3. Run validation on sample output
4. Update version/build date if significant changes

---

## Version History Notes

### v7.0.0 (2025-10-28) - Current
- Fix extraction rebuilt with better namespace handling
- Remediation import rewritten for bulk JSON (array/object payloads)
- XML sanitizer hardened (no silent truncation)
- All write paths atomic with rollback
- GUI/CLI UX improvements

### Development Focus Areas
1. **Robustness** - Handle malformed input gracefully
2. **Air-gap** - No external dependencies ever
3. **Compliance** - STIG Viewer 2.18 compatibility mandatory
4. **Performance** - Optimize for 15,000 vulnerability checklists

---

## Quick Reference

### File Locations
| Component | Path |
|-----------|------|
| Main script | `/home/user/STIG_Script/STIG_Script.py` |
| Logs | `~/.stig_assessor/logs/` |
| Backups | `~/.stig_assessor/backups/` |
| Evidence | `~/.stig_assessor/evidence/` |
| Templates | `~/.stig_assessor/templates/boilerplate.json` |

### Key Line Numbers (STIG_Script.py v7.4.3)
| Component | Line Range |
|-----------|------------|
| Constants | 127-195 |
| Enums (Status/Severity) | 197-235 |
| GlobalState | 237-355 |
| Errors | 357-387 |
| Retry Decorator | 389-442 |
| Dependencies | 445-540 |
| Configuration | 542-713 |
| Logging | 715-859 |
| XML Schema | 861-967 |
| XML Utils | 969-1208 |
| Sanitization | 1210-1572 |
| File Operations | 1574-1884 |
| History | 1886-2296 |
| Boilerplate | 2298-2524 |
| Validation | 2526-2695 |
| Main Processor | 2697-3930 |
| Fix Extraction | 3932-4598 |
| Remediation | 4600-4907 |
| Evidence | 4909-5224 |
| Presets | 5226-5276 |
| GUI | 5278-6427 |
| Utility | 6429-6437 |
| CLI Entry | 6440-6776 |

### Status Values (Case-Sensitive)
- `NotAFinding` - Control satisfied
- `Open` - Control not satisfied
- `Not_Applicable` - Control not applicable
- `Not_Reviewed` - Not yet assessed

### Severity Levels
- `high` - CAT I
- `medium` - CAT II
- `low` - CAT III

---

## AI Assistant Behavioral Guidelines

### When Analyzing Code
1. Always check line numbers in this guide
2. Read surrounding context (±50 lines)
3. Understand XML structure before modifying
4. Test changes with verbose logging enabled

### When Adding Features
1. Maintain single-file architecture (air-gap requirement)
2. Use existing patterns (see similar features)
3. Add to CLI and GUI simultaneously (feature parity)
4. Update version number and build date
5. Document in module docstring

### When Fixing Bugs
1. Identify root cause in logs (`~/.stig_assessor/logs/`)
2. Check if validation error (STIG Viewer compatibility)
3. Preserve existing functionality (regression testing)
4. Add defensive checks (don't assume input validity)

### When Documenting
1. Update this CLAUDE.md file
2. Update module docstring (lines 3-32)
3. Keep language concise and technical
4. Include code examples for complex features

---

## Additional Resources

### STIG Resources
- **STIG Viewer:** Official DoD checklist viewer (validates CKL files)
- **XCCDF Format:** Open Checklist Interactive Language (SCAP content)
- **CKL Format:** STIG Viewer proprietary XML format

### Python Documentation
- **Minimum Version:** Python 3.9
- **Required Modules:** All stdlib (json, xml, pathlib, logging, etc.)
- **Optional:** tkinter (GUI only)

### Related Standards
- **SCAP:** Security Content Automation Protocol
- **XCCDF:** Extensible Configuration Checklist Description Format
- **CVE:** Common Vulnerabilities and Exposures
- **CCI:** Control Correlation Identifier

---

## Maintenance Checklist

### Monthly
- [ ] Review and clean old backups (`Cfg.cleanup_old()`)
- [ ] Review log files for recurring errors
- [ ] Test with latest STIG benchmarks

### Per Release
- [ ] Update `VERSION` constant (line 70)
- [ ] Update `BUILD_DATE` constant (line 71)
- [ ] Update module docstring (lines 3-32)
- [ ] Test all CLI workflows
- [ ] Test all GUI workflows
- [ ] Validate output with STIG Viewer

### Before Production Deployment
- [ ] Test on target platform (Windows/Linux)
- [ ] Verify air-gap operation (no network access)
- [ ] Test with large files (15,000 vulnerabilities)
- [ ] Verify backup/restore functionality
- [ ] Test evidence packaging workflow

---

**Last Updated:** 2026-01-02
**Repository:** Maddesea/STIG_Script
**Current Branch:** claude/improve-project-pj6D9
