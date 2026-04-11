# STIG Assessor Complete — Definitive User Guide

**Version 8.1.0** · Build Date: 2026-04-07 · STIG Viewer Compatibility: 2.18 / 3.3 (CKLB)

> The single source of truth for operating STIG Assessor from installation through
> fleet-wide compliance tracking in air-gapped, high-side, or cloud environments.

---

## Table of Contents

| # | Section | Quick Jump |
|---|---------|-----------|
| 1 | [Installation & Prerequisites](#1-installation--prerequisites) | Setup, Python, dependencies |
| 2 | [Launching the Application](#2-launching-the-application) | CLI, GUI, Web — all three methods |
| 3 | [Interface Overview](#3-interface-overview) | Which interface to choose and when |
| 4 | [Phase A — Creating a Checklist from XCCDF](#4-phase-a--creating-a-checklist-from-xccdf) | Convert benchmarks to CKL/CKLB |
| 5 | [Phase B — Merging & Updating Checklists](#5-phase-b--merging--updating-checklists) | Quarterly STIG updates |
| 6 | [Phase C — Extracting Remediation Scripts](#6-phase-c--extracting-remediation-scripts) | Bash, PowerShell, Ansible, CSV, JSON |
| 7 | [Phase D — Applying Remediation Results](#7-phase-d--applying-remediation-results) | Bulk import scan results |
| 8 | [Phase E — Evidence Management](#8-phase-e--evidence-management) | Import, export, package artifacts |
| 9 | [Phase F — Validation & Repair](#9-phase-f--validation--repair) | Fix corrupted CKLs |
| 10 | [Phase G — Compliance Statistics & Reporting](#10-phase-g--compliance-statistics--reporting) | Text, JSON, CSV, HTML reports |
| 11 | [Phase H — Comparing (Diffing) Checklists](#11-phase-h--comparing-diffing-checklists) | Before/after analysis |
| 12 | [Phase I — Integrity Verification](#12-phase-i--integrity-verification) | SHA-256 checksums and tamper detection |
| 13 | [Phase J — Boilerplate Template Management](#13-phase-j--boilerplate-template-management) | Standardized finding text |
| 14 | [Phase K — History & Compliance Drift Tracking](#14-phase-k--history--compliance-drift-tracking) | SQLite database, drift analysis |
| 15 | [Phase L — Batch Operations & Fleet Dashboard](#15-phase-l--batch-operations--fleet-dashboard) | At-scale processing |
| 16 | [Phase M — Bulk Edit & POAM Export](#16-phase-m--bulk-edit--poam-export) | Mass-update VIDs, eMASS POAM CSV |
| 17 | [Phase N — Format Conversion (CKL ↔ CKLB)](#17-phase-n--format-conversion-ckl--cklb) | STIG Viewer 2 vs 3 formats |
| 18 | [Phase O — Profile & Configuration Management](#18-phase-o--profile--configuration-management) | Save/Load/Export/Import profiles |
| 19 | [GUI-Specific Features](#19-gui-specific-features) | Tabs, themes, presets, shortcuts |
| 20 | [Web Interface](#20-web-interface) | Browser-based operations |
| 21 | [Scripting & Automation Recipes](#21-scripting--automation-recipes) | Pipeline examples |
| 22 | [Troubleshooting](#22-troubleshooting) | Common issues and fixes |
| 23 | [Configuration Reference](#23-configuration-reference) | Directories, limits, env vars |
| 24 | [Glossary](#24-glossary) | Key terms |

---

## 1. Installation & Prerequisites

### 1.1 System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| **Python** | 3.9 | 3.12+ |
| **OS** | Windows 10, macOS 11+, Linux | Windows 11, any recent Linux |
| **RAM** | 512 MB | 2 GB (for large checklists) |
| **Disk** | 50 MB | 200 MB (with evidence store) |
| **Network** | **None** (fully air-gapped) | None |

### 1.2 Dependencies

STIG Assessor is deliberately **zero-dependency** for air-gapped use. It runs entirely on the Python standard library.

| Dependency | Required? | Purpose |
|------------|----------|---------|
| Python stdlib | ✅ Yes | Core functionality |
| `tkinter` | ⚠️ GUI only | Graphical interface (usually built-in on Windows/macOS) |
| `defusedxml` | 🔒 Recommended | Protection against XXE/Billion Laughs XML attacks |
| `sv_ttk` | ❌ Optional | Premium GUI theme (Sun Valley ttk theme) |

**Install recommended extras:**
```bash
# Secure XML parsing (strongly recommended for DoD environments)
pip install defusedxml

# Premium GUI theme (optional, cosmetic only)
pip install sv_ttk

# GUI support on Linux (if not already installed)
sudo apt install python3-tk          # Debian/Ubuntu
sudo dnf install python3-tkinter     # RHEL/Fedora
```

### 1.3 Installation Methods

#### Method A: Clone the Repository
```bash
git clone https://github.com/Maddesea/STIG_Script.git
cd STIG_Script
```

#### Method B: Air-Gap / Portable Deployment
1. Copy the entire `STIG_Script/` folder to your target machine via approved media.
2. Optionally place a portable Python installation in a `python/` subfolder (the launchers auto-detect it).
3. No `pip install` required — the tool works immediately.

#### Method C: Standalone Executable
For maximum air-gapped simplicity, build or download the standalone executable (`STIG_Assessor.exe`). All features work from this single binary without requiring Python:
```cmd
.\STIG_Assessor.exe --help
```

### 1.4 Verifying Your Installation
```bash
# Installed via pip (or running from venv)
stig-assessor --version

# Running directly from source package (no install)
python -m stig_assessor --version

# Running standalone executable
.\STIG_Assessor.exe --version
```

Expected output: `8.1.0`

---

## 2. Launching the Application

STIG Assessor supports **three interfaces**: CLI, GUI, and Web. All three have full feature parity.

### 2.1 Command-Line Interface (CLI)

```bash
# Installed via pip (or running from venv)
stig-assessor --help

# Running directly from source package (no install)
python -m stig_assessor --help

# Running standalone executable
.\STIG_Assessor.exe --help

# With verbose logging
stig-assessor --verbose --create --xccdf benchmark.xml --asset SRV01
```

### 2.1.1 Interactive Wizard Mode (CLI)

The CLI features a fully interactive menu-driven Wizard for guided operations. It includes an **Advanced End-to-End Pipeline** option that chains checklist building, remediation application, and HTML reporting automatically.

```bash
# Launch the interactive Wizard mode
stig-assessor --wizard
```

### 2.2 Graphical Interface (GUI)

```bash
# Launch GUI
stig-assessor --gui

# Windows: Double-click the launcher
launch_gui.bat

# PowerShell launcher
.\launch.ps1                     # Default: GUI mode
.\launch.ps1 -Mode gui
```

### 2.3 Web Interface

```bash
# Launch web server (auto-opens browser)
stig-assessor --web

# Windows: Double-click the launcher
launch_web.bat

# PowerShell
.\launch.ps1 -Mode web
```

The web server starts on `http://127.0.0.1:8080` (it tries ports 8080–8089 if occupied). Your default browser opens automatically.

### 2.4 Windows Launcher Scripts

| File | Purpose |
|------|---------|
| `launch_gui.bat` | Double-click to open the GUI on Windows |
| `launch_web.bat` | Double-click to open the Web interface on Windows |
| `launch.ps1` | PowerShell launcher with `-Mode gui/web/cli` parameter |

All launchers auto-detect Python from:
1. `./venv/` (Local virtual environment)
2. `./python/python.exe` (Portable)
3. `./python312/python.exe` (Portable, version-specific)
4. System-installed `python` on PATH (offers to create venv from `wheels/` if deps are missing)

---

## 3. Interface Overview

### When to Use Each Interface

| Interface | Best For | Automation? | Air-Gap? |
|-----------|---------|-------------|----------|
| **CLI** | Scripting, pipelines, batch ops, CI/CD | ✅ Full | ✅ |
| **GUI** | Interactive assessment work, single-file ops | ❌ Manual | ✅ |
| **Web** | Modern experience, team demos, file-upload workflow | ❌ Manual | ✅ |

### CLI Quick Reference

```
stig-assessor [GLOBAL_OPTIONS] [COMMAND] [COMMAND_OPTIONS]

Global Options:
  --version          Show version number
  --verbose / -v     Enable debug-level logging
  --gui              Launch the graphical interface
  --web              Launch the web interface

Commands:
  --create           Create CKL from XCCDF
  --create-cklb      Create CKLB (JSON) from XCCDF
  --merge            Merge checklists with history
  --extract          Extract fixes from XCCDF
  --apply-results    Import remediation results
  --validate         Validate a checklist
  --repair           Fix corrupted checklists
  --diff             Compare two checklists
  --stats            Generate compliance statistics
  --verify-integrity Checksum + validate
  --batch-convert    Batch convert a folder of XCCDFs
  --fleet-stats      Fleet-wide compliance stats
  --bulk-edit        Mass-update matching VIDs
  --export-poam      Export eMASS POAM CSV
  --import-evidence / --export-evidence / --package-evidence
  --track-ckl / --show-drift
  --bp-list / --bp-set / --bp-delete / --bp-export / --bp-import / --bp-reset / --bp-clone
  --save-profile / --use-profile / --export-configs / --import-configs
  --convert-to-cklb / --convert-to-ckl
  --compute-checksum
```

---

## 4. Phase A — Creating a Checklist from XCCDF

Converts a DISA XCCDF benchmark (`.xml`) into a STIG Viewer-compatible checklist (`.ckl` or `.cklb`).

### 4.1 CLI

```bash
stig-assessor --create \
  --xccdf U_RHEL_8_STIG_V1R10_Manual-xccdf.xml \
  --asset "WEB-SERVER-01" \
  --ip "10.0.1.50" \
  --mac "00:1A:2B:3C:4D:5E" \
  --role "Member Server" \
  --marking "CUI" \
  --apply-boilerplate \
  --out WEB-SERVER-01_RHEL8.ckl
```

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--xccdf` | ✅ | — | Path to the XCCDF `.xml` benchmark file |
| `--asset` | ✅ | — | Hostname or asset identifier for the system |
| `--out` | ❌ | `{asset}_{xccdf_stem}.ckl` | Output file path |
| `--ip` | ❌ | `""` | IP address |
| `--mac` | ❌ | `""` | MAC address |
| `--role` | ❌ | `"None"` | System role (e.g., "Member Server", "Web Server") |
| `--marking` | ❌ | `"CUI"` | Classification marking (CUI, FOUO, SECRET, etc.) |
| `--apply-boilerplate` | ❌ | `false` | Pre-populate finding details with template text |
| `--dry-run` | ❌ | `false` | Test the conversion without writing any file |

#### Creating a CKLB (STIG Viewer 3) file instead:
```bash
stig-assessor --create-cklb \
  --xccdf benchmark.xml \
  --asset "SRV-01"
```

#### Interactive Mode
If you run `--create` without `--xccdf` or `--asset`, and you're in a terminal (not a pipe), the tool will **prompt** you for the missing values interactively.

#### Understanding the Output
```json
{
  "ok": true,
  "output": "/path/to/WEB-SERVER-01_RHEL8.ckl",
  "processed": 287,
  "skipped": 0,
  "errors": []
}
```

### 4.2 GUI

1. Launch the GUI (`stig-assessor --gui`).
2. Navigate to the **📋 Create CKL** tab.
3. Click **📂 Browse…** to select your `.xml` XCCDF file.
4. Enter your **Asset Name** (required, shown with red `* Required` validation).
5. Optionally enter IP, MAC, and select a Marking from the dropdown.
6. Check **☑ Apply boilerplate templates** if desired.
7. Click **➕ Create Checklist**.
8. The result appears in the output log at the bottom.

### 4.3 Web

1. Launch the web server (`stig-assessor --web`).
2. Go to the **Create CKL** section.
3. Drag-and-drop or browse for your XCCDF file.
4. Fill in asset details.
5. Click **Convert**. The browser downloads the resulting `.ckl` file.

---

## 5. Phase B — Merging & Updating Checklists

When DISA releases a new quarterly STIG, you must migrate your historical assessment data (comments, statuses, finding details) onto the new baseline. The merge feature does this automatically.

### 5.1 CLI

```bash
stig-assessor --merge \
  --base Q4_2025_Blank_Baseline.ckl \
  --histories Q1_Assessment.ckl Q2_Assessment.ckl Q3_Assessment.ckl \
  --merge-out Q4_2025_Preserved.ckl
```

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--merge` | ✅ | — | Enable merge mode |
| `--base` | ✅ | — | The new blank baseline checklist |
| `--histories` | ✅ | — | One or more previous assessments (space-separated) |
| `--merge-out` | ❌ | `{base_stem}_merged.ckl` | Output path |
| `--no-preserve-history` | ❌ | `false` | Do NOT inject formatted history into finding details |
| `--no-boilerplate` | ❌ | `false` | Do NOT fill empty fields with boilerplate text |
| `--merge-dry-run` | ❌ | `false` | Preview changes without writing |

#### How Merge Works (Detailed)

1. The tool parses each history file chronologically.
2. For each vulnerability ID found in the history files, it records:
   - Status, finding details, comments, severity, and the source filename.
3. When applying to the base checklist, for each VULN:
   - If `preserve_history=true`: A formatted history block is prepended to finding details.
   - If `apply_boilerplate=true`: Empty fields are filled with template text.
   - The most recent status is preserved.
4. History entries are deduplicated — identical entries from multiple files are merged.

#### Example Output
```json
{
  "updated": 215,
  "skipped": 72,
  "dry_run": false,
  "output": "/path/to/Q4_2025_Preserved.ckl"
}
```

### 5.2 GUI

1. Navigate to the **🔀 Merge Checklists** tab.
2. Browse for your **Base Checklist** (the new STIG release).
3. Click **Add…** to add one or more history files. Remove/Clear as needed.
4. Set your output path.
5. Options:
   - **☑ Preserve full history** — includes formatted assessment history in finding details.
   - **☑ Apply boilerplates when missing** — fills blank fields with defaults.
6. Click **🔀 Merge Checklists**.

---

## 6. Phase C — Extracting Remediation Scripts

Parses XCCDF benchmarks for embedded fix instructions and exports them as ready-to-execute scripts.

### 6.1 CLI

```bash
stig-assessor --extract benchmark.xml \
  --outdir ./server_fixes \
  --script-dry-run \
  --enable-rollbacks
```

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--extract` | ✅ | — | Path to XCCDF file |
| `--outdir` | ❌ | `{xccdf_stem}_fixes/` | Output directory |
| `--no-json` | ❌ | `false` | Disable JSON export |
| `--no-csv` | ❌ | `false` | Disable CSV export |
| `--no-bash` | ❌ | `false` | Disable Bash script |
| `--no-ps` | ❌ | `false` | Disable PowerShell script |
| `--no-ansible` | ❌ | `false` | Disable Ansible playbook |
| `--script-dry-run` | ❌ | `false` | Scripts print commands without executing |
| `--enable-rollbacks` | ❌ | `false` | PowerShell: creates registry backups before changes |

#### Generated Output Files

| File | Description |
|------|-------------|
| `fixes.json` | Complete structured data (VID, severity, commands, CCI refs) |
| `fixes.csv` | Spreadsheet-friendly summary |
| `remediate.sh` | Linux Bash script with logging and result JSON output |
| `Remediate.ps1` | Windows PowerShell with transcript, optional rollbacks |
| `remediate.yml` | Ansible playbook tasks |

#### Command Extraction Intelligence

The extractor uses **12 pattern engines** to find commands in fix text:
1. Markdown code blocks (```)
2. Shell prompts (`$`, `#`, `>`)
3. PowerShell prompts (`PS C:\>`)
4. Bullet-style instructions ("Run: ...")
5. Inline code (`` ` ``)
6. "Run the following command:" blocks
7. Common UNIX commands (chmod, systemctl, grep, etc.)
8. PowerShell cmdlets (Set-*, Get-*, New-*, etc.)
9. Registry commands (`reg add`, `reg query`)
10. File editing instructions
11. Windows Group Policy paths
12. Multi-line command blocks

#### Platform Detection

Each fix is tagged with a platform (`linux`, `windows`, `network`, or `generic`) based on keywords in the fix text.

### 6.2 GUI

1. Navigate to **🔧 Extract Fixes** tab.
2. Browse for your XCCDF file and set the output directory.
3. Toggle output formats with checkboxes.
4. Check **Dry run mode** for non-destructive scripts.
5. Click **🔧 Extract Fixes**.

---

## 7. Phase D — Applying Remediation Results

After running your remediation scripts (or third-party scanners), import the results back into your checklist to bulk-update statuses, finding details, and comments.

### 7.1 Results JSON Format

The expected format is a JSON array of result objects:
```json
[
  {
    "vid": "V-230234",
    "ok": true,
    "msg": "Successfully configured audit settings",
    "ts": "2026-01-15T10:30:00Z"
  },
  {
    "vid": "V-230235",
    "ok": false,
    "msg": "Failed: permission denied",
    "ts": "2026-01-15T10:30:05Z"
  }
]
```

Or a CSV file with columns: `vid`, `ok` (true/false), `msg`, `ts`.

### 7.2 CLI

```bash
# Single file
stig-assessor --apply-results results.json \
  --checklist server01.ckl \
  --results-out server01_updated.ckl

# Multiple results files from different scanners
stig-assessor --apply-results scan_a.json scan_b.json manual_check.json \
  --checklist server01.ckl \
  --results-out server01_final.ckl

# Fine-grained text injection
stig-assessor --apply-results results.json \
  --checklist server01.ckl \
  --details-mode append \
  --comment-mode prepend
```

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--apply-results` | ✅ | — | One or more JSON/CSV result files |
| `--checklist` | ✅ | — | Target CKL to update |
| `--results-out` | ❌ | `{checklist_stem}_updated.ckl` | Output path |
| `--no-auto-status` | ❌ | `false` | Do NOT auto-mark successes as `NotAFinding` |
| `--results-dry-run` | ❌ | `false` | Preview without writing |
| `--details-mode` | ❌ | `prepend` | How to inject finding details: `prepend`, `append`, or `overwrite` |
| `--comment-mode` | ❌ | `prepend` | How to inject comments: `prepend`, `append`, or `overwrite` |

#### Text Injection Modes Explained

| Mode | Behavior |
|------|----------|
| `prepend` | New result text is added **before** existing content (separated by newlines) |
| `append` | New result text is added **after** existing content |
| `overwrite` | Existing content is **replaced entirely** with new result text |

### 7.3 GUI

1. Navigate to **📥 Import Results**.
2. Select your results JSON file and your target CKL.
3. Set the output path.
4. Check **Auto-mark successes as NotAFinding** (enabled by default).
5. Click **Import Results**.

### 7.4 Generating Results with the Wizard

```bash
# Interactive wizard
python scripts/generate_remediation.py

# Convert CSV output from a scanner
python scripts/generate_remediation.py --from-csv scan_output.csv --output results.json
```

---

## 8. Phase E — Evidence Management

The Evidence Manager provides content-deduplicated storage for screenshots, logs, and audit artifacts organized by vulnerability ID.

### 8.1 CLI

```bash
# Import a single evidence file
stig-assessor --import-evidence "V-230234" /path/to/firewall_screenshot.png \
  --evidence-desc "firewalld status showing drop rules" \
  --evidence-cat "config"

# Export all evidence to a directory
stig-assessor --export-evidence /path/to/export_dir

# Create a ZIP package for auditors or transfer
stig-assessor --package-evidence evidence_bundle.zip

# Import evidence from a received package
stig-assessor --import-evidence-package received_evidence.zip
```

#### Parameters

| Parameter | Description |
|-----------|-------------|
| `--import-evidence VID FILE` | Import a file for the specified vulnerability ID |
| `--evidence-desc "text"` | Description for the imported evidence |
| `--evidence-cat "category"` | Category label (e.g., `config`, `screenshot`, `log`, `scan`) |
| `--export-evidence DIR` | Export all stored evidence to a directory |
| `--package-evidence FILE.zip` | Bundle all evidence into a deduplicated ZIP |
| `--import-evidence-package FILE.zip` | Import evidence from a ZIP package |

### 8.2 GUI

1. Navigate to the **📎 Evidence** tab.
2. Enter the target V-ID.
3. Add a description and browse to select a file.
4. Click **Import**.
5. Use the **Package** button to export everything as a ZIP.

### 8.3 Storage Location

All evidence is stored under `~/.stig_assessor/evidence/`, organized by VID subdirectories with a `manifest.json` metadata file.

---

## 9. Phase F — Validation & Repair

### 9.1 Validation

Checks a CKL for STIG Viewer 2.18 compatibility issues that would cause import errors.

#### CLI
```bash
stig-assessor --validate assessment.ckl
```

**Output:**
```json
{
  "ok": true,
  "errors": [],
  "warnings": ["Finding details length > 60000 chars for V-230501"],
  "info": ["Total 287 vulnerabilities validated"]
}
```

Exit code: `0` = valid, `1` = has errors.

#### What is Validated
- Root element is `CHECKLIST`
- `ASSET`, `STIGS`, `iSTIG`, `STIG_INFO`, `VULN` elements exist
- All required ASSET fields present (`HOST_NAME`, `TARGET_KEY`, etc.)
- Status values are valid (`NotAFinding`, `Open`, `Not_Applicable`, `Not_Reviewed`)
- Finding details and comments are within length limits
- No invalid XML characters
- STIG_DATA has proper `VULN_ATTRIBUTE` / `ATTRIBUTE_DATA` pairs

### 9.2 Repair

Automatically fixes common corruption issues in CKL files.

#### CLI
```bash
stig-assessor --repair corrupt_assessment.ckl \
  --repair-out fixed_assessment.ckl
```

#### What is Repaired
1. **Invalid status values** — Fixes typos like `"not_a_finding"` → `"NotAFinding"`, `"open"` → `"Open"`.
2. **Missing ASSET elements** — Adds required fields with sensible defaults.
3. **Oversized content** — Truncates finding details >65,000 chars and comments >32,000 chars (prevents STIG Viewer crashes).

#### GUI
1. Navigate to the **🔧 Repair CKL** tab.
2. Select the corrupt file and set an output path.
3. Click **Repair**. A detailed log of all repairs is displayed.

---

## 10. Phase G — Compliance Statistics & Reporting

### 10.1 CLI

```bash
# Text report to console
stig-assessor --stats assessment.ckl

# JSON output (machine-readable)
stig-assessor --stats assessment.ckl --stats-format json

# Save to file
stig-assessor --stats assessment.ckl --stats-format html --stats-out report.html

# CSV for spreadsheets
stig-assessor --stats assessment.ckl --stats-format csv --stats-out stats.csv
```

#### Output Formats

| Format | Description |
|--------|-------------|
| `text` | Human-readable console report with status/severity breakdown |
| `json` | Full statistics as a JSON object (total, by_status, by_severity, completion %) |
| `csv` | CSV with metric/value rows |
| `html` | **Self-contained HTML report** with donut chart, severity table, and key metrics. Printable to PDF. |

#### Text Report Example
```
================================================================================
STIG Compliance Statistics
================================================================================
File: /path/to/assessment.ckl
Generated: 2026-04-07 12:00:00 UTC

Total Vulnerabilities: 287
Reviewed: 250 (87.1%)
Compliant: 230 (92.0% of reviewed)

Status Breakdown:
----------------------------------------
  NotAFinding          230 ( 80.1%)
  Not_Applicable        12 (  4.2%)
  Not_Reviewed          37 ( 12.9%)
  Open                   8 (  2.8%)

Severity Breakdown:
----------------------------------------
  CAT I   (high  )     45 ( 15.7%)
  CAT II  (medium)    195 ( 67.9%)
  CAT III (low   )     47 ( 16.4%)
================================================================================
```

### 10.2 GUI

1. Navigate to the **📊 Analytics** tab.
2. Select a CKL file.
3. View status counts, severity breakdown, and per-finding detail table.
4. Alternatively: **Tools → Checklist Statistics…** from the menu bar.

### 10.3 Web

1. Upload a CKL on the **Analytics** page.
2. Interactive charts and a filterable findings table are displayed.
3. Download the HTML report.

---

## 11. Phase H — Comparing (Diffing) Checklists

### 11.1 CLI

```bash
# Summary comparison
stig-assessor --diff previous.ckl current.ckl

# Detailed comparison showing all unique VIDs
stig-assessor --diff previous.ckl current.ckl --diff-format detailed

# Machine-readable JSON
stig-assessor --diff previous.ckl current.ckl --diff-format json
```

#### What is Compared
- **Status changes** — e.g., `Open` → `NotAFinding`
- **Severity changes** — e.g., `medium` → `high`
- **Finding details and comments changes** (length comparison)
- **VIDs only in one checklist** (new/removed rules)

### 11.2 GUI

1. Navigate to the **🔍 Compare** tab (or **Tools → Compare Checklists…**).
2. Select two CKL files.
3. View a formatted diff report.

---

## 12. Phase I — Integrity Verification

### 12.1 Verify Integrity

Combines SHA-256 checksum computation with full STIG Viewer validation.

```bash
stig-assessor --verify-integrity final_assessment.ckl
```

**Output:**
```json
{
  "valid": true,
  "file": "/path/to/final_assessment.ckl",
  "size": 1548237,
  "checksum": "a1b2c3d4e5f6...SHA256 hex digest...",
  "checksum_type": "SHA256",
  "validation_errors": 0,
  "validation_warnings": 0
}
```

### 12.2 Compute Checksum Only

```bash
stig-assessor --compute-checksum assessment.ckl
# Output: a1b2c3d4...  assessment.ckl
```

---

## 13. Phase J — Boilerplate Template Management

Boilerplates are reusable text templates applied to finding details and comments based on vulnerability ID and status. They support Python format-string placeholders (`{asset}`, `{severity}`).

### 13.1 Template Structure

Templates are organized as:
```json
{
  "V-*": {
    "NotAFinding": {
      "finding_details": "This control is satisfied. Evidence: {asset}",
      "comments": "Reviewed by automated script."
    },
    "Open": {
      "finding_details": "This control is not satisfied. Findings: [describe issue]",
      "comments": "Remediation pending for {asset}."
    },
    "Not_Applicable": {
      "finding_details": "This control does not apply because: [justification]",
      "comments": "Not applicable to {asset} configuration."
    }
  },
  "V-230234": {
    "NotAFinding": {
      "finding_details": "Audit logging is properly configured.",
      "comments": "Verified via 'auditctl -l'."
    }
  }
}
```

- `V-*` = **Global wildcard** — applies to all VIDs unless a specific VID override exists.
- Per-VID templates **override** the global wildcard for matching statuses.

### 13.2 CLI Commands

```bash
# List all boilerplates
stig-assessor --bp-list

# List boilerplates for a specific VID
stig-assessor --bp-list-vid V-230234

# Set a boilerplate
stig-assessor --bp-set \
  --vid V-230234 \
  --status NotAFinding \
  --finding "Audit logging is configured correctly." \
  --comment "Verified via manual inspection."

# Delete a boilerplate
stig-assessor --bp-delete --vid V-230234 --status NotAFinding
# Or delete ALL statuses for a VID:
stig-assessor --bp-delete --vid V-230234

# Clone templates from one VID to another
stig-assessor --bp-clone V-230234 V-230235

# Export all boilerplates to a JSON file
stig-assessor --bp-export boilerplates_backup.json

# Import boilerplates from a JSON file (merges with existing)
stig-assessor --bp-import team_templates.json

# Reset ALL boilerplates to factory defaults
stig-assessor --bp-reset
```

### 13.3 Apply Modes (used during Create/Merge)

| Mode | Behavior |
|------|----------|
| `overwrite_empty` | Only fills in **empty** fields (default during creation) |
| `prepend` | Adds boilerplate text **before** existing content |
| `append` | Adds boilerplate text **after** existing content |
| `merge` | Combines with existing text, separated by `--- Boilerplate ---` divider |

### 13.4 Template Variables

| Variable | Substituted With |
|----------|-----------------|
| `{asset}` | Asset hostname or identifier |
| `{severity}` | Vulnerability severity level (high/medium/low) |

### 13.5 GUI

1. Navigate to the **📝 Boilerplates** tab.
2. View, add, edit, or delete boilerplate entries.
3. Use the **Tools** menu for Import/Export.

### 13.6 Storage

Templates are stored at `~/.stig_assessor/templates/boilerplate.json`. This file is auto-created with factory defaults on first run.

---

## 14. Phase K — History & Compliance Drift Tracking

### 14.1 Tracking Assessments

Ingest a completed checklist into the SQLite history database for long-term tracking:

```bash
stig-assessor --track-ckl completed_assessment.ckl
```

This extracts all VID statuses and stores them with a timestamp and asset name.

### 14.2 Viewing Compliance Drift

Compare the latest assessment against previous ones:

```bash
stig-assessor --show-drift "WEB-SERVER-01"
```

**Output:**
```
=== Compliance Drift for WEB-SERVER-01 ===
Fixed (Open -> NotAFinding): 12
Regressed (NotAFinding -> Open): 2
Changed: 3
New Rules: 15
Removed Rules: 0
Unchanged: 260
```

### 14.3 History Export/Import

```bash
# Export history to JSON
stig-assessor --export-history history_backup.json

# Import history from JSON
stig-assessor --import-history received_history.json
```

### 14.4 GUI

1. Navigate to the **📈 History/Drift** tab.
2. Upload a CKL to track, or select an asset name to view drift analysis.

### 14.5 Web

1. Use the **History** section.
2. Upload a CKL to ingest.
3. Select an asset to view compliance drift trends.

### 14.6 Database Location

`~/.stig_assessor/history/stig_history.db` (SQLite)

---

## 15. Phase L — Batch Operations & Fleet Dashboard

### 15.1 Batch Convert XCCDFs to CKLs

Process an entire folder of XCCDF benchmarks at once:

```bash
# Basic batch conversion
stig-assessor --batch-convert /path/to/stig_folder/ \
  --batch-out /path/to/ckl_output/ \
  --batch-asset-prefix "DC01"

# With boilerplate application
stig-assessor --batch-convert /path/to/stigs/ \
  --batch-out /path/to/ckls/ \
  --batch-asset-prefix "WEB" \
  --apply-boilerplate

# Output as CKLB (STIG Viewer 3)
stig-assessor --batch-convert /path/to/stigs/ \
  --batch-out-ext .cklb
```

#### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--batch-convert DIR` | — | Directory containing XCCDF `.xml` files |
| `--batch-out DIR` | `{dir_name}_ckls/` | Output directory |
| `--batch-asset-prefix` | `"ASSET"` | Prefix for auto-generated asset names |
| `--batch-out-ext` | `.ckl` | Output format: `.ckl` or `.cklb` |

### 15.2 Fleet Statistics

Analyze compliance across an entire fleet of checklists:

```bash
# From a directory
stig-assessor --fleet-stats /path/to/fleet_ckls/

# From a ZIP archive
stig-assessor --fleet-stats fleet_bundle.zip
```

**Output:** JSON with aggregate compliance stats across all assets, including per-asset breakdowns and overall fleet compliance percentage.

### 15.3 GUI

1. Navigate to the **🏭 Batch Convert** tab.
2. Select a folder of XCCDFs and an output directory.
3. Click **Convert All**.

### 15.4 Web

1. Use the **Fleet Dashboard** section.
2. Upload a ZIP of CKLs.
3. View aggregated compliance charts and per-asset breakdowns.

---

## 16. Phase M — Bulk Edit & POAM Export

### 16.1 Bulk Edit

Mass-update vulnerabilities matching specific criteria:

```bash
# Mark all CAT III (low) items as Not_Applicable
stig-assessor --bulk-edit assessment.ckl \
  --filter-severity low \
  --apply-status Not_Applicable \
  --apply-comment "Low-severity items deferred per site policy." \
  --bulk-out assessment_updated.ckl

# Mark specific VIDs matching a regex
stig-assessor --bulk-edit assessment.ckl \
  --filter-vid "V-2302[0-9]{2}" \
  --apply-status NotAFinding \
  --apply-comment "Remediated in batch 2026-Q1." \
  --append-comment
```

#### Parameters

| Parameter | Description |
|-----------|-------------|
| `--bulk-edit FILE` | Checklist to modify |
| `--bulk-out FILE` | Output path (default: `{stem}_updated.ckl`) |
| `--filter-severity` | Filter by `high`, `medium`, or `low` |
| `--filter-vid` | Filter by VID regex pattern |
| `--apply-status` | Status to apply: `NotAFinding`, `Open`, `Not_Applicable`, `Not_Reviewed` |
| `--apply-comment` | Comment text to apply |
| `--append-comment` | Append to existing comments instead of replacing |

### 16.2 eMASS POAM Export

Export Open and Not_Reviewed findings as an eMASS-compatible Plan of Action & Milestones CSV:

```bash
stig-assessor --export-poam assessment.ckl
```

**Output:** Creates `assessment_poam.csv` with columns:
- Control Number (VID)
- Vulnerability Description (Rule Title)
- Severity
- Status
- Comments
- Checklist Name

---

## 17. Phase N — Format Conversion (CKL ↔ CKLB)

Convert between STIG Viewer 2 (`.ckl`, XML) and STIG Viewer 3 (`.cklb`, JSON) formats:

```bash
# CKL → CKLB
stig-assessor --convert-to-cklb existing_assessment.ckl

# CKLB → CKL  
stig-assessor --convert-to-ckl existing_assessment.cklb
```

The output file is created alongside the input with the opposite extension.

---

## 18. Phase O — Profile & Configuration Management

### 18.1 Assessment Profiles

Save and reuse common argument configurations:

```bash
# Save current arguments as a profile
stig-assessor --save-profile "rhel8_web_servers" \
  --create --xccdf rhel8.xml --asset "WEB-" --marking "CUI" --apply-boilerplate

# Use a saved profile
stig-assessor --use-profile "rhel8_web_servers" \
  --asset "WEB-SERVER-42" --out web42.ckl
```

Profiles are stored in `~/.stig_assessor/presets/{profile_name}.json`.

### 18.2 Configuration Bundles (Import/Export)

Bundle all boilerplates, profiles, and plugin configurations for transfer:

```bash
# Export all configs
stig-assessor --export-configs team_configs.zip

# Import configs on a new machine
stig-assessor --import-configs team_configs.zip
```

This creates/reads a ZIP containing `presets/`, `boilerplates/`, and `plugins/` directories.

---

## 19. GUI-Specific Features

### 19.1 Tab Layout

The GUI contains **12 tabs**:

| Tab | Function |
|-----|----------|
| 📋 Create CKL | XCCDF → CKL conversion |
| 🔀 Merge Checklists | Merge with history |
| 🔧 Extract Fixes | Remediation script export |
| 📥 Import Results | Bulk apply remediation |
| 📎 Evidence | Evidence management |
| ✅ Validate | CKL validation |
| 🔧 Repair CKL | Fix corrupted checklists |
| 🏭 Batch Convert | Bulk XCCDF → CKL |
| 📝 Boilerplates | Template management |
| 🔍 Compare | Checklist diffing |
| 📊 Analytics | Statistics & reporting |
| 📈 History/Drift | Compliance drift tracking |

### 19.2 Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` through `Ctrl+6` | Switch to tab 1–6 |
| `Ctrl+Enter` | Execute the current tab's primary action |
| `Ctrl+S` | Save preset |
| `Ctrl+O` | Load preset |
| `Ctrl+Q` / `Escape` | Exit |
| `Ctrl+,` | Open Settings |

### 19.3 Theme Support

- **Light Mode** and **Dark Mode** — toggle via **View → Toggle Dark/Light Mode**.
- If `sv_ttk` is installed, a premium Sun Valley theme is applied automatically.
- Theme preference is saved between sessions in `~/.stig_assessor/settings.json`.

### 19.4 Wizard Mode

Enable via **View → Wizard Mode**. Displays a step-by-step workflow bar guiding you through: ① Create → ② Remediate → ③ Merge → ④ Validate.

### 19.5 Menu Bar

| Menu | Key Items |
|------|-----------|
| **File** | Save/Load/Delete Presets, Recent Files, Exit |
| **View** | Toggle Theme, Wizard Mode |
| **Tools** | Export/Import History, Export/Import Boilerplates, Cleanup Old Files, Statistics, Compare, Settings |
| **Help** | Quick-Start Guide, About |

### 19.6 Logo Support

Place a `.png` logo image and reference it in the Settings dialog to display an organization banner in the GUI header and as the taskbar icon (Windows).

---

## 20. Web Interface

### 20.1 Architecture

The web interface runs a built-in HTTP server (`http://127.0.0.1:8080`) using Python's `http.server` module — **zero external dependencies**. It serves a static single-page application (SPA) that communicates with a REST API.

### 20.2 API Endpoints

All API calls use `POST /api/v1/{endpoint}` with JSON payloads. File content is base64-encoded.

| Endpoint | Function |
|----------|----------|
| `/api/v1/ping` | Health check |
| `/api/v1/xccdf_to_ckl` | Create CKL from XCCDF |
| `/api/v1/merge_ckls` | Merge checklists |
| `/api/v1/apply_results` | Apply remediation results |
| `/api/v1/extract` | Extract fixes |
| `/api/v1/diff` | Compare two checklists |
| `/api/v1/stats` | Generate compliance statistics |
| `/api/v1/validate` | Validate a CKL |
| `/api/v1/repair` | Repair a CKL |
| `/api/v1/verify_integrity` | Integrity verification |
| `/api/v1/bulk_edit` | Bulk edit VIDs |
| `/api/v1/export_poam` | eMASS POAM export |
| `/api/v1/fleet_stats` | Fleet compliance from ZIP |
| `/api/v1/track_ckl` | Ingest CKL into history DB |
| `/api/v1/show_drift` | Get compliance drift |
| `/api/v1/list_assets` | List tracked assets |
| `/api/v1/bp_list` / `bp_set` / `bp_delete` / `bp_export` / `bp_import` / `bp_reset` | Boilerplate management |
| `/api/v1/evidence/summary` / `evidence/import` / `evidence/package` | Evidence management |

### 20.4 Payload Size Limit

Maximum POST payload: **50 MB** (`MAX_POST_PAYLOAD`). Requests exceeding this limit receive HTTP 413.

---

## 21. Scripting & Automation Recipes

### Recipe 1: Full Assessment Pipeline

```bash
#!/usr/bin/env bash
set -euo pipefail

XCCDF="U_RHEL_8_STIG_V1R10_Manual-xccdf.xml"
ASSET="APP-SERVER-42"
CKL="${ASSET}_baseline.ckl"
FIXES_DIR="${ASSET}_fixes"
RESULTS="remediation_results.json"
FINAL="${ASSET}_assessed.ckl"

# Step 1: Create baseline checklist
stig-assessor --create --xccdf "$XCCDF" --asset "$ASSET" \
  --apply-boilerplate --out "$CKL"

# Step 2: Extract remediation scripts
stig-assessor --extract "$XCCDF" --outdir "$FIXES_DIR"

# Step 3: Execute fixes (generates results JSON)
sudo bash "${FIXES_DIR}/remediate.sh"

# Step 4: Import results back into checklist
stig-assessor --apply-results "${FIXES_DIR}/stig_results_*.json" \
  --checklist "$CKL" --results-out "$FINAL"

# Step 5: Generate compliance report
stig-assessor --stats "$FINAL" --stats-format html --stats-out "${ASSET}_report.html"

# Step 6: Verify integrity
stig-assessor --verify-integrity "$FINAL"

# Step 7: Track into history
stig-assessor --track-ckl "$FINAL"

echo "Pipeline complete for $ASSET"
```

### Recipe 2: Quarterly STIG Update Migration

```bash
# New quarterly STIG release
NEW_XCCDF="U_RHEL_8_STIG_V1R11_Manual-xccdf.xml"
NEW_BLANK="blank_v1r11.ckl"

# Create blank baseline from new XCCDF
stig-assessor --create --xccdf "$NEW_XCCDF" --asset "TEMP" --out "$NEW_BLANK"

# Merge all previous assessments
stig-assessor --merge \
  --base "$NEW_BLANK" \
  --histories Q1_assessment.ckl Q2_assessment.ckl Q3_assessment.ckl \
  --merge-out Q4_assessment.ckl

# Validate the result
stig-assessor --validate Q4_assessment.ckl
```

### Recipe 3: Fleet Batch Processing

```bash
# Convert all STIGs for a fleet
for server in WEB{01..10}; do
  stig-assessor --create \
    --xccdf win_server_2022_stig.xml \
    --asset "$server" \
    --out "fleet/$server.ckl" \
    --apply-boilerplate
done

# Generate fleet-wide statistics
stig-assessor --fleet-stats fleet/
```

### Recipe 4: CI/CD Validation Gate

```bash
# In your CI pipeline:
result=$(stig-assessor --stats assessment.ckl --stats-format json)
compliance=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['compliance_pct'])")

if (( $(echo "$compliance < 80" | bc -l) )); then
  echo "FAIL: Compliance at ${compliance}% (minimum: 80%)"
  exit 1
fi
echo "PASS: Compliance at ${compliance}%"
```

---

## 22. Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `"Cannot find writable home directory"` | Check permissions on `$HOME`, `$USERPROFILE`, or `/tmp` |
| `"XML parser failed"` | Verify `xml.etree.ElementTree` is included in your Python installation |
| `"Invalid CKL structure"` | Run `--validate` to identify schema violations, then `--repair` |
| `"tkinter not available"` | Install `python3-tk` package (Linux) or reinstall Python with tkinter (macOS Homebrew: `brew install python-tk`) |
| Web server fails to start | Port 8080 is in use; the server auto-tries ports 8080–8089 |
| `"No vulnerability groups found"` | The XML file is not a valid XCCDF benchmark; it may be a CKL or other format |
| Large file is slow | Files >50MB trigger chunked processing; this is normal for 15,000+ vulnerability checklists |

### Verbose Logging

```bash
stig-assessor --verbose [any command]
```

Logs are written to `~/.stig_assessor/logs/stig_assessor.log` (rotating, 10 MB max, 15 files retained).

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (validation failure, file error, etc.) |
| `2` | Partial success (some files failed in batch operations) |
| `130` | Operation cancelled by user (Ctrl+C) |

---

## 23. Configuration Reference

### Directory Structure

All runtime data is stored under `~/.stig_assessor/`:

```
~/.stig_assessor/
├── logs/              # Application logs (rotating, 10MB max)
├── backups/           # Automatic CKL backups (.bak files)
├── evidence/          # Evidence file storage (organized by VID)
├── templates/         # Boilerplate templates (boilerplate.json)
├── presets/           # Saved configuration presets
├── fixes/             # Extracted remediation scripts
├── exports/           # Export outputs
├── history/           # SQLite history database
├── plugins/           # Plugin directory
└── settings.json      # GUI preferences (theme, logo, etc.)
```

Directory resolution order:
1. `Path.home()` (standard)
2. `$USERPROFILE` or `$HOME` environment variables
3. `$TMPDIR/stig_user` (fallback)
4. `$CWD/.stig_home` (last resort)

### Processing Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_FILE_SIZE` | 500 MB | Maximum file size |
| `MAX_FINDING_LENGTH` | 65,000 chars | Maximum finding details length |
| `MAX_COMMENT_LENGTH` | 32,000 chars | Maximum comments length |
| `MAX_HISTORY_ENTRIES` | 200 | Maximum history entries per VID |
| `MAX_MERGE_FILES` | 100 | Maximum checklists to merge |
| `MAX_VULNERABILITIES` | 15,000 | Maximum VULNs per checklist |
| `KEEP_BACKUPS` | 30 | Backup file retention count |
| `KEEP_LOGS` | 15 | Log file retention count |
| `MAX_POST_PAYLOAD` | 50 MB | Web API max POST size |

### Supported File Formats

| Extension | Format | Notes |
|-----------|--------|-------|
| `.xml` | XCCDF Benchmark | Input for creation and fix extraction |
| `.ckl` | STIG Viewer 2 Checklist | XML format, primary output |
| `.cklb` | STIG Viewer 3 Checklist | JSON format, newer standard |
| `.json` | Remediation Results / History | Various data interchange |
| `.csv` | Remediation Results / Stats | Spreadsheet-compatible |
| `.zip` | Evidence Packages / Fleet Bundles | Compressed archives |

---

## 24. Glossary

| Term | Definition |
|------|-----------|
| **XCCDF** | Extensible Configuration Checklist Description Format — the source benchmark format from DISA |
| **CKL** | Checklist — STIG Viewer's proprietary XML format |
| **CKLB** | Checklist (JSON) — STIG Viewer 3's new JSON-based format |
| **STIG** | Security Technical Implementation Guide — DoD security configuration standards |
| **VID / V-ID** | Vulnerability Identifier, e.g., `V-230234` |
| **CAT I / II / III** | Severity categories: CAT I (High), CAT II (Medium), CAT III (Low) |
| **CCI** | Control Correlation Identifier — maps STIGs to NIST 800-53 controls |
| **NotAFinding** | Status indicating the system meets the security requirement |
| **Open** | Status indicating the system does NOT meet the requirement |
| **Not_Applicable** | Status indicating the requirement doesn't apply to this system |
| **Not_Reviewed** | Default status — assessment not yet performed |
| **POAM** | Plan of Action & Milestones — required DoD remediation tracking document |
| **eMASS** | Enterprise Mission Assurance Support Service — DoD risk management platform |
| **Boilerplate** | Reusable template text for finding details and comments |
| **Air-gapped** | Environments with no network connectivity to external systems |

---

## Appendix A: Quick Command Cheat Sheet

```bash
# ───────────── CREATION ─────────────
--create --xccdf FILE --asset NAME [--out FILE] [--apply-boilerplate] [--dry-run]
--create-cklb --xccdf FILE --asset NAME

# ───────────── CONVERSION ─────────────
--convert-to-cklb FILE.ckl
--convert-to-ckl  FILE.cklb

# ───────────── MERGE ─────────────
--merge --base FILE --histories FILE [FILE ...] [--merge-out FILE] [--merge-dry-run]

# ───────────── EXTRACT ─────────────
--extract FILE.xml [--outdir DIR] [--script-dry-run] [--enable-rollbacks]

# ───────────── REMEDIATION ─────────────
--apply-results FILE [FILE ...] --checklist FILE [--results-out FILE]
    [--details-mode prepend|append|overwrite]
    [--comment-mode prepend|append|overwrite]
    [--no-auto-status] [--results-dry-run]

# ───────────── EVIDENCE ─────────────
--import-evidence VID FILE [--evidence-desc TEXT] [--evidence-cat CAT]
--export-evidence DIR
--package-evidence FILE.zip
--import-evidence-package FILE.zip

# ───────────── VALIDATION ─────────────
--validate FILE
--repair FILE [--repair-out FILE]
--verify-integrity FILE
--compute-checksum FILE

# ───────────── STATISTICS ─────────────
--stats FILE [--stats-format text|json|csv|html] [--stats-out FILE]
--fleet-stats DIR_OR_ZIP

# ───────────── COMPARISON ─────────────
--diff FILE1 FILE2 [--diff-format summary|detailed|json]

# ───────────── HISTORY ─────────────
--track-ckl FILE
--show-drift ASSET_NAME
--export-history FILE
--import-history FILE

# ───────────── BOILERPLATE ─────────────
--bp-list
--bp-list-vid VID
--bp-set --vid VID --status STATUS [--finding TEXT] [--comment TEXT]
--bp-delete --vid VID [--status STATUS]
--bp-clone FROM_VID TO_VID
--bp-export FILE
--bp-import FILE
--bp-reset

# ───────────── BULK OPERATIONS ─────────────
--batch-convert DIR [--batch-out DIR] [--batch-asset-prefix PREFIX] [--batch-out-ext .ckl|.cklb]
--bulk-edit FILE --apply-status STATUS --apply-comment TEXT
    [--filter-severity high|medium|low] [--filter-vid REGEX] [--append-comment] [--bulk-out FILE]
--export-poam FILE

# ───────────── PROFILE MANAGEMENT ─────────────
--save-profile NAME
--use-profile NAME
--export-configs FILE.zip
--import-configs FILE.zip

# ───────────── INTERFACE ─────────────
--gui
--web
--verbose / -v
--version
```

---

*Generated for STIG Assessor Complete v8.1.0 · Air-Gap Certified · Zero Dependencies · MIT License*
