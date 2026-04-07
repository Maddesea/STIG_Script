# STIG Assessor API Documentation

**Version:** 8.0.0 (Modular Architecture)
**Date:** 2025-11-16
**Python:** 3.9+

---

## Table of Contents

1. [Introduction](#introduction)
2. [Core Modules](#core-modules)
3. [XML Processing](#xml-processing)
4. [File Operations](#file-operations)
5. [Validation](#validation)
6. [History Management](#history-management)
7. [Templates](#templates)
8. [Main Processor](#main-processor)
9. [Remediation](#remediation)
10. [Evidence Management](#evidence-management)
11. [User Interface](#user-interface)
12. [Error Handling](#error-handling)
13. [Examples](#examples)

---

## Introduction

The STIG Assessor API provides programmatic access to all STIG assessment functionality. The modular architecture allows you to use individual components or the complete workflow.

### Installation

```bash
# Install from source
git clone https://github.com/Maddesea/STIG_Script.git
cd STIG_Script
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH=/path/to/STIG_Script:$PYTHONPATH
```

### Quick Start

```python
from stig_assessor.processor.processor import Proc
from pathlib import Path

# Create processor
proc = Proc()

# Convert XCCDF to CKL
proc.xccdf_to_ckl(
    xccdf=Path("benchmark.xml"),
    output=Path("checklist.ckl"),
    asset_name="SERVER-01",
    ip="192.168.1.100",
    mac="00:11:22:33:44:55",
    role="Member Server"
)
```

---

## Core Modules

### GlobalState (stig_assessor.core.state)

Singleton for process-wide state management and shutdown coordination.

```python
from stig_assessor.core.state import GlobalState, GLOBAL_STATE

# Get singleton instance
state = GlobalState()  # Same as GLOBAL_STATE

# Check shutdown status
if not state.is_shutdown():
    # Do work
    process_data()

# Trigger shutdown
state.shutdown()

# Register cleanup callback
def cleanup():
    print("Cleaning up...")

state.register_cleanup(cleanup)
```

**API:**
- `is_shutdown() -> bool` - Check if shutdown flag is set
- `shutdown() -> None` - Set shutdown flag and call cleanup callbacks
- `register_cleanup(callback: Callable) -> None` - Register cleanup function

**Thread Safety:** ✅ Thread-safe (uses RLock)

---

### Cfg (stig_assessor.core.config)

Configuration and directory management.

```python
from stig_assessor.core.config import Cfg, CFG

# Get singleton instance
cfg = Cfg()  # Same as CFG

# Access directories
print(f"Logs: {cfg.log_dir}")
print(f"Backups: {cfg.backup_dir}")
print(f"Evidence: {cfg.evidence_dir}")

# Cleanup old files
cfg.cleanup_old_backups()  # Keep 30 most recent
cfg.cleanup_old_logs()     # Keep 15 most recent
```

**API:**
- `home_dir: Path` - User home directory
- `stig_dir: Path` - ~/.stig_assessor/
- `log_dir: Path` - ~/.stig_assessor/logs/
- `backup_dir: Path` - ~/.stig_assessor/backups/
- `evidence_dir: Path` - ~/.stig_assessor/evidence/
- `template_dir: Path` - ~/.stig_assessor/templates/
- `cleanup_old_backups() -> int` - Returns number deleted
- `cleanup_old_logs() -> int` - Returns number deleted

**Thread Safety:** ❌ Not thread-safe (use from main thread only)

---

### Log (stig_assessor.core.logging)

Thread-safe rotating file logger.

```python
from stig_assessor.core.logging import Log, LOG

# Get singleton instance
log = Log()  # Same as LOG

# Log messages
LOG.debug("Detailed debug information")
LOG.info("General information")
LOG.warning("Warning message")
LOG.error("Error occurred", exc_info=True)
LOG.critical("Critical failure")

# Context logging
LOG.info("Processing VID", extra={"vid": "V-123456", "status": "Open"})
```

**API:**
- `debug(msg: str, **kwargs) -> None`
- `info(msg: str, **kwargs) -> None`
- `warning(msg: str, **kwargs) -> None`
- `error(msg: str, **kwargs) -> None`
- `critical(msg: str, **kwargs) -> None`

**Features:**
- Rotating file handler (10MB max, 5 backups)
- Thread-safe logging
- Console and file output
- Contextual metadata support

**Thread Safety:** ✅ Thread-safe

---

### Deps (stig_assessor.core.deps)

Dependency detection for optional components.

```python
from stig_assessor.core.deps import Deps

# Check dependencies
if Deps.has_tkinter():
    from stig_assessor.ui.gui import GUI
    gui = GUI()
    gui.run()
else:
    print("GUI not available (tkinter missing)")

if Deps.has_defusedxml():
    # Use defusedxml for enhanced security
    pass
else:
    # Fall back to standard ElementTree
    pass
```

**API:**
- `has_tkinter() -> bool` - Check if tkinter available
- `has_defusedxml() -> bool` - Check if defusedxml available
- `get_xml_parser() -> module` - Get best available XML parser

---

## XML Processing

### Sch (stig_assessor.xml.schema)

XML schema definitions and namespace resolution.

```python
from stig_assessor.xml.schema import Sch
import xml.etree.ElementTree as ET

# Parse with namespaces
tree = ET.parse("benchmark.xml")
root = tree.getroot()

# Find elements with namespace
groups = root.findall(".//ns:Group", Sch.NS)
for group in groups:
    title = group.find("ns:title", Sch.NS)
    print(title.text if title is not None else "")

# Get namespace URI
xccdf_ns = Sch.ns("xccdf")  # Returns full namespace URI
```

**API:**
- `NS: Dict[str, str]` - Namespace dictionary for findall/find
- `ns(prefix: str) -> str` - Get full namespace URI
- `XCCDF_ELEMENTS: Set[str]` - Valid XCCDF element names
- `CKL_ELEMENTS: Set[str]` - Valid CKL element names

---

### San (stig_assessor.xml.sanitizer)

XML sanitization and input validation.

```python
from stig_assessor.xml.sanitizer import San

# Sanitize text for XML
safe_text = San.txt("<script>alert('xss')</script>")
# Result: "&lt;script&gt;alert('xss')&lt;/script&gt;"

# Comprehensive XML escaping
safe_xml = San.xml_safe("Value with <, >, &, ', and \"")

# Truncate long text
truncated = San.trunc("A" * 100000, max_len=65000)

# Validate IP addresses
if San.is_valid_ip("192.168.1.100"):
    print("Valid IP")

# Validate MAC addresses
if San.is_valid_mac("00:11:22:33:44:55"):
    print("Valid MAC")

# Normalize status values
status = San.normalize_status("notafinding")  # Returns: "NotAFinding"

# Normalize severity
severity = San.normalize_severity("cat ii")  # Returns: "medium"
```

**API:**
- `txt(text: Optional[str]) -> str` - Escape dangerous XML characters
- `xml_safe(text: str) -> str` - Comprehensive XML escaping
- `trunc(text: str, max_len: int) -> str` - Truncate with ellipsis
- `is_valid_ip(ip: str) -> bool` - Validate IPv4 address
- `is_valid_mac(mac: str) -> bool` - Validate MAC address
- `normalize_status(status: str) -> str` - Normalize to valid status
- `normalize_severity(severity: str) -> str` - Normalize to valid severity

**Thread Safety:** ✅ Thread-safe (stateless functions)

---

## File Operations

### FO (stig_assessor.io.file_ops)

Atomic file operations with backup and rollback.

```python
from stig_assessor.io.file_ops import FO
from pathlib import Path

# Atomic write with automatic backup
content = "<?xml version='1.0'?>..."
FO.atomic_write(
    path=Path("checklist.ckl"),
    content=content,
    backup=True  # Creates .bak file
)

# Read with encoding fallback
content = FO.read_with_fallback(Path("checklist.ckl"))

# Save XML tree
import xml.etree.ElementTree as ET
tree = ET.parse("input.xml")
FO.save_xml(tree, Path("output.xml"), backup=True)

# Create backup manually
backup_path = FO.create_backup(Path("important.ckl"))
print(f"Backup created: {backup_path}")
```

**API:**
- `atomic_write(path: Path, content: str, backup: bool = False) -> None`
- `read_with_fallback(path: Path) -> str` - Try UTF-8, then UTF-16, then latin-1
- `save_xml(tree: ET.ElementTree, path: Path, backup: bool = False) -> None`
- `create_backup(path: Path) -> Path` - Returns backup path
- `detect_encoding(path: Path) -> str` - Detect file encoding

**Features:**
- Atomic writes (write to temp, then rename)
- Automatic backups before overwrite
- Encoding detection and fallback
- Symlink attack prevention
- Rollback on failure

**Thread Safety:** ✅ Thread-safe (atomic operations)

---

## Validation

### Val (stig_assessor.validation.validator)

STIG Viewer 2.18 compatibility validation.

```python
from stig_assessor.validation.validator import Val
from pathlib import Path

# Validate CKL structure
try:
    Val.validate_ckl(Path("checklist.ckl"))
    print("✓ Valid CKL structure")
except ValidationError as e:
    print(f"✗ Validation failed: {e}")

# Validate XCCDF
try:
    Val.validate_xccdf(Path("benchmark.xml"))
    print("✓ Valid XCCDF structure")
except ValidationError as e:
    print(f"✗ Validation failed: {e}")

# Check error threshold
errors = ["Error 1", "Error 2", "Error 3"]
Val.check_error_threshold(errors, max_errors=10, context="merge")
```

**API:**
- `validate_ckl(path: Path) -> None` - Raises ValidationError if invalid
- `validate_xccdf(path: Path) -> None` - Raises ValidationError if invalid
- `check_error_threshold(errors: List[str], max_errors: int, context: str) -> None`

**Validation Rules:**
- CKL must have CHECKLIST root
- Required elements: ASSET, STIGS, iSTIG, STIG_INFO, VULN
- Valid status values: NotAFinding, Open, Not_Applicable, Not_Reviewed
- Valid severity: high, medium, low

**Thread Safety:** ✅ Thread-safe (stateless validation)

---

## History Management

### Hist (stig_assessor.history.models)

Individual history entry (immutable dataclass).

```python
from stig_assessor.history.models import Hist
from datetime import datetime

# Create history entry
entry = Hist(
    timestamp=datetime.now(),
    status="NotAFinding",
    finding_details="Service is enabled and running",
    comments="Verified via systemctl status",
    username="admin"
)

# Access fields
print(f"Status: {entry.status}")
print(f"Time: {entry.timestamp.isoformat()}")

# Serialize to XML element
xml_element = entry.to_xml()

# Parse from XML element
entry2 = Hist.from_xml(xml_element)
```

**API:**
- `timestamp: datetime` - When entry was created
- `status: str` - Status value
- `finding_details: str` - Finding details
- `comments: str` - Comments
- `username: str` - Who made the change
- `to_xml() -> ET.Element` - Serialize to XML
- `from_xml(element: ET.Element) -> Hist` - Deserialize from XML

---

### HistMgr (stig_assessor.history.manager)

History lifecycle management with deduplication.

```python
from stig_assessor.history.manager import HistMgr
from stig_assessor.history.models import Hist

# Create manager
mgr = HistMgr(max_entries=200)

# Add entry (automatic deduplication)
mgr.add(Hist(
    timestamp=datetime.now(),
    status="Open",
    finding_details="Issue found",
    comments="Needs remediation",
    username="admin"
))

# Get all entries (chronological order)
entries = mgr.get_all()

# Get latest entry
latest = mgr.get_latest()

# Merge from another manager
other_mgr = HistMgr()
# ... populate other_mgr ...
mgr.merge(other_mgr)

# Serialize/deserialize
xml_elements = mgr.to_xml_list()
mgr2 = HistMgr.from_xml_list(xml_elements)
```

**API:**
- `add(entry: Hist) -> None` - Add entry (deduplicated)
- `get_all() -> List[Hist]` - Get all entries (chronological)
- `get_latest() -> Optional[Hist]` - Get most recent entry
- `merge(other: HistMgr) -> None` - Merge entries from another manager
- `to_xml_list() -> List[ET.Element]` - Serialize all entries
- `from_xml_list(elements: List[ET.Element]) -> HistMgr` - Deserialize

**Features:**
- Content-based deduplication
- Chronological ordering (bisect insertion)
- Maximum entry limit (keeps most recent)
- Microsecond-precision timestamps

**Thread Safety:** ❌ Not thread-safe (use locks if needed)

---

## Templates

### BP (stig_assessor.templates.boilerplate)

Boilerplate template management.

```python
from stig_assessor.templates.boilerplate import BP
from pathlib import Path

# Load templates
bp = BP()
bp.load(Path("~/.stig_assessor/templates/boilerplate.json"))

# Get template
template = bp.get("V-123456", "NotAFinding")
if template:
    print(f"Template: {template}")

# Set template
bp.set("V-123456", "Open", "Service is not enabled. Enable with: systemctl enable httpd")

# Save templates
bp.save(Path("~/.stig_assessor/templates/boilerplate.json"))

# Apply to CKL
bp.apply_to_ckl(
    ckl_path=Path("checklist.ckl"),
    output_path=Path("checklist_with_templates.ckl")
)
```

**API:**
- `load(path: Path) -> None` - Load templates from JSON
- `save(path: Path) -> None` - Save templates to JSON
- `get(vid: str, status: str) -> Optional[str]` - Get template text
- `set(vid: str, status: str, template: str) -> None` - Set template
- `apply_to_ckl(ckl_path: Path, output_path: Path) -> int` - Returns count applied

---

## Main Processor

### Proc (stig_assessor.processor.processor)

Main processor for XCCDF→CKL conversion, merging, and more.

```python
from stig_assessor.processor.processor import Proc
from pathlib import Path

# Create processor
proc = Proc()

# Convert XCCDF to CKL
proc.xccdf_to_ckl(
    xccdf=Path("benchmark.xml"),
    output=Path("checklist.ckl"),
    asset_name="SERVER-01",
    ip="192.168.1.100",
    mac="00:11:22:33:44:55",
    role="Member Server",
    marking="CUI",
    apply_boilerplate=True
)

# Merge checklists
proc.merge(
    base=Path("current.ckl"),
    histories=[Path("old1.ckl"), Path("old2.ckl")],
    output=Path("merged.ckl")
)

# Diff two checklists
diff = proc.diff(
    old=Path("checklist_v1.ckl"),
    new=Path("checklist_v2.ckl")
)
for vid, changes in diff.items():
    print(f"{vid}: {changes}")

# Generate statistics
stats = proc.statistics(Path("checklist.ckl"))
print(f"Total VULNs: {stats['total']}")
print(f"Open: {stats['open']}, NaF: {stats['naf']}")
```

**API:**
- `xccdf_to_ckl(...) -> None` - Convert XCCDF to CKL
- `merge(base: Path, histories: List[Path], output: Path) -> None`
- `diff(old: Path, new: Path) -> Dict[str, Dict[str, Any]]`
- `statistics(ckl: Path) -> Dict[str, int]`
- `repair(ckl: Path, output: Path) -> int` - Fix common issues

---

## Remediation

### Fix (stig_assessor.remediation.models)

Single remediation fix (immutable dataclass).

```python
from stig_assessor.remediation.models import Fix

# Create fix
fix = Fix(
    vid="V-123456",
    title="Enable HTTP service",
    severity="medium",
    commands=["systemctl enable httpd", "systemctl start httpd"],
    description="Enable and start Apache HTTP server"
)

# Access fields
print(f"VID: {fix.vid}")
print(f"Commands: {', '.join(fix.commands)}")
```

---

### FixExt (stig_assessor.remediation.extractor)

Extract remediation fixes from XCCDF.

```python
from stig_assessor.remediation.extractor import FixExt
from pathlib import Path

# Create extractor
extractor = FixExt(xccdf_path=Path("benchmark.xml"))

# Extract fixes
fixes = extractor.extract()
print(f"Extracted {len(fixes)} fixes")

# Export to JSON
json_path = extractor.to_json(Path("fixes.json"))

# Export to CSV
csv_path = extractor.to_csv(Path("fixes.csv"))

# Generate Bash script
bash_path = extractor.to_bash(Path("remediate.sh"), dry_run=True)

# Generate PowerShell script
ps_path = extractor.to_powershell(Path("Remediate.ps1"), dry_run=True)
```

**API:**
- `extract() -> List[Fix]` - Extract all fixes from XCCDF
- `to_json(path: Path) -> Path` - Export to JSON
- `to_csv(path: Path) -> Path` - Export to CSV
- `to_bash(path: Path, dry_run: bool = False) -> Path` - Generate Bash script
- `to_powershell(path: Path, dry_run: bool = False) -> Path` - Generate PS script

---

### FixResPro (stig_assessor.remediation.processor)

Remediation results processor - import bulk fixes.

```python
from stig_assessor.remediation.processor import FixResPro
from pathlib import Path

# Create processor
processor = FixResPro()

# Load results from JSON
processor.load(Path("remediation_results.json"))

# Update CKL with results
updated_ckl = processor.update_ckl(
    ckl_path=Path("checklist.ckl"),
    output_path=Path("checklist_updated.ckl")
)

print(f"Updated {processor.count_applied()} VULNs")

# Generate report
report = processor.generate_report()
print(report)
```

**API:**
- `load(path: Path) -> None` - Load results from JSON
- `update_ckl(ckl_path: Path, output_path: Path) -> Path`
- `count_applied() -> int` - Count how many results applied
- `generate_report() -> str` - Generate summary report

**JSON Format:**
```json
{
  "results": [
    {
      "vid": "V-123456",
      "status": "NotAFinding",
      "finding_details": "Fix applied successfully",
      "comments": "Automated remediation"
    }
  ]
}
```

---

## Evidence Management

### EvidenceMgr (stig_assessor.evidence.manager)

Evidence file import, export, and packaging.

```python
from stig_assessor.evidence.manager import EvidenceMgr
from pathlib import Path

# Create manager
mgr = EvidenceMgr(base_dir=Path("~/.stig_assessor/evidence"))

# Import evidence file
mgr.import_file(
    vid="V-123456",
    file_path=Path("screenshot.png"),
    description="System configuration screenshot",
    category="config"
)

# Import multiple files for same VID
mgr.import_file("V-123456", Path("log.txt"), "System log", "logs")

# Export all evidence
mgr.export_all(output_dir=Path("evidence_export"))

# Package evidence to ZIP
mgr.package(output_path=Path("evidence.zip"))

# List evidence for VID
evidence = mgr.list_for_vid("V-123456")
for e in evidence:
    print(f"{e.filename}: {e.description}")
```

**API:**
- `import_file(vid: str, file_path: Path, description: str, category: str) -> None`
- `export_all(output_dir: Path) -> int` - Returns count exported
- `package(output_path: Path) -> Path` - Create ZIP package
- `list_for_vid(vid: str) -> List[EvidenceMeta]`
- `delete(vid: str, filename: str) -> None`

**Features:**
- Hash-based deduplication
- Metadata persistence (JSON)
- Organized by VID
- ZIP packaging with manifest

---

## Error Handling

### Exception Hierarchy

```python
from stig_assessor.exceptions import (
    STIGError,          # Base exception
    ValidationError,    # Validation failures
    FileError,          # File I/O errors
    ParseError          # XML parsing errors
)

# Catch specific errors
try:
    proc.xccdf_to_ckl(...)
except ValidationError as e:
    print(f"Validation failed: {e}")
except FileError as e:
    print(f"File error: {e}")
except STIGError as e:
    print(f"General STIG error: {e}")
```

---

## Examples

### Example 1: Complete XCCDF to CKL Workflow

```python
from stig_assessor.processor.processor import Proc
from stig_assessor.templates.boilerplate import BP
from pathlib import Path

# Initialize
proc = Proc()
bp = BP()
bp.load(Path("~/.stig_assessor/templates/boilerplate.json"))

# Convert XCCDF to CKL
proc.xccdf_to_ckl(
    xccdf=Path("benchmarks/RHEL_8_STIG.xml"),
    output=Path("checklists/rhel8_baseline.ckl"),
    asset_name="RHEL-WEB-01",
    ip="10.0.1.50",
    mac="00:50:56:AB:CD:EF",
    role="Web Server",
    marking="CUI"
)

# Apply boilerplate templates
bp.apply_to_ckl(
    ckl_path=Path("checklists/rhel8_baseline.ckl"),
    output_path=Path("checklists/rhel8_with_templates.ckl")
)

print("✓ CKL created with templates")
```

### Example 2: Merge Multiple Assessments

```python
from stig_assessor.processor.processor import Proc
from pathlib import Path

proc = Proc()

# Merge multiple assessment iterations
proc.merge(
    base=Path("checklists/current.ckl"),
    histories=[
        Path("checklists/2025-01.ckl"),
        Path("checklists/2025-02.ckl"),
        Path("checklists/2025-03.ckl"),
    ],
    output=Path("checklists/merged.ckl")
)

print("✓ Assessments merged with history preserved")
```

### Example 3: Full Remediation Workflow

```python
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro
from pathlib import Path
import subprocess
import json

# Step 1: Extract fixes from benchmark
extractor = FixExt(xccdf_path=Path("benchmark.xml"))
extractor.extract()
json_path = extractor.to_json(Path("fixes.json"))
bash_path = extractor.to_bash(Path("remediate.sh"), dry_run=False)

print(f"✓ Fixes extracted to {json_path}")
print(f"✓ Remediation script: {bash_path}")

# Step 2: Execute remediation (simulated)
# subprocess.run(["bash", str(bash_path)], capture_output=True)

# Step 3: Create results (simulated)
results = {
    "results": [
        {
            "vid": "V-123456",
            "status": "NotAFinding",
            "finding_details": "Service enabled via systemctl",
            "comments": "Automated remediation successful"
        },
        {
            "vid": "V-234567",
            "status": "Open",
            "finding_details": "Remediation failed: permission denied",
            "comments": "Requires manual intervention"
        }
    ]
}

results_path = Path("results.json")
results_path.write_text(json.dumps(results, indent=2))

# Step 4: Import results to CKL
processor = FixResPro()
processor.load(results_path)
processor.update_ckl(
    ckl_path=Path("checklist.ckl"),
    output_path=Path("checklist_remediated.ckl")
)

print(f"✓ Updated {processor.count_applied()} findings")
```

### Example 4: Evidence Management

```python
from stig_assessor.evidence.manager import EvidenceMgr
from pathlib import Path

mgr = EvidenceMgr()

# Import evidence for multiple VIDs
evidence_items = [
    ("V-123456", "screenshots/firewall_config.png", "Firewall settings", "config"),
    ("V-123456", "logs/firewall.log", "Firewall audit log", "logs"),
    ("V-234567", "screenshots/selinux_status.png", "SELinux status", "config"),
]

for vid, file_path, desc, cat in evidence_items:
    mgr.import_file(vid, Path(file_path), desc, cat)
    print(f"✓ Imported {file_path}")

# Package everything
package_path = mgr.package(Path("evidence_package.zip"))
print(f"✓ Evidence packaged: {package_path}")
```

---

## Best Practices

### 1. Always Use Context Managers for Resources

```python
# Good
from pathlib import Path

path = Path("file.txt")
content = path.read_text()  # Automatically closed

# Also good with explicit try/finally
try:
    content = FO.read_with_fallback(path)
finally:
    # Cleanup if needed
    pass
```

### 2. Enable Verbose Logging for Debugging

```python
from stig_assessor.core.logging import LOG
import logging

# Set debug level
LOG.setLevel(logging.DEBUG)

# Your operations here
proc.xccdf_to_ckl(...)
```

### 3. Validate Files After Operations

```python
from stig_assessor.validation.validator import Val

# After creating CKL
proc.xccdf_to_ckl(...)
Val.validate_ckl(output_path)  # Verify it's valid
```

### 4. Use Atomic Operations for Critical Files

```python
from stig_assessor.io.file_ops import FO

# Always create backups
FO.atomic_write(path, content, backup=True)
```

### 5. Handle Exceptions Appropriately

```python
from stig_assessor.exceptions import ValidationError, FileError

try:
    proc.merge(base, histories, output)
except ValidationError as e:
    LOG.error(f"Validation failed: {e}")
    # Handle validation error
except FileError as e:
    LOG.error(f"File error: {e}")
    # Handle file error
```

---

## Performance Tips

1. **Batch Operations**: Process multiple files in one call when possible
2. **Memory Management**: For large files (15K+ VULNs), call `gc.collect()` after processing
3. **Concurrent Processing**: Most operations are thread-safe - use ThreadPoolExecutor
4. **Caching**: Reuse Proc, BP, and other manager instances

---

## Versioning

This API follows semantic versioning:
- **Major**: Breaking API changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

Current version: **8.0.0**

---

## Support

- **Documentation**: See `CLAUDE.md`, `DEV_QUICK_START.md`, `MODULARIZATION_SPEC.md`
- **Issues**: https://github.com/Maddesea/STIG_Script/issues
- **Discussions**: https://github.com/Maddesea/STIG_Script/discussions

---

**Last Updated:** 2025-11-16
**Maintained By:** STIG Assessor Development Team
