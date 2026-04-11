# STIG Assessor GUI Usage Guide

This guide provides detailed instructions on how to use the **STIG Assessor** graphical user interface (GUI). The GUI has been redesigned to improve usability, layout, and visual consistency.

## 🚀 Launching the GUI

To start the graphical interface, run the script with the `--gui` flag:

```bash
python -m stig_assessor --gui
```

*Note: Ensure you have `python3-tk` installed on your system.*

## 🖥️ Interface Overview

The interface is organized into logical tabs for different workflows.

*   **Global Status Bar**: Located at the very bottom of the window, this bar provides real-time feedback on operations (e.g., "Processing…", "Success", "Error"). An **animated progress indicator** appears during long-running operations.
*   **Menu Bar**:
    *   **File**: Save/Load/Delete presets, Exit.
    *   **Tools**: Import/Export history, Manage boilerplate templates, Cleanup old files.
    *   **Help**: Application information.

---

## 📑 Tab Guide

### 1. 📋 Create CKL
*Convert an XCCDF benchmark file into a STIG Viewer checklist (CKL).*

*   **Files Section**:
    *   **XCCDF File**: Browse for the source `.xml` benchmark file.
    *   **Output CKL**: Select where to save the generated checklist.
*   **Asset Details**:
    *   **Asset Name**: (Required) The hostname of the system being assessed.
    *   **IP / MAC**: Optional network details.
    *   **Marking**: Classification marking (e.g., CUI, PROPRIETARY).
    *   **Apply Boilerplate**: Check this to automatically populate findings with default templates. *(Hover for tooltip)*
*   **Feedback**: After creation, a summary dialog shows processed/skipped VID counts and any errors.

### 2. 🔀 Merge Checklists
*Combine multiple checklists into a single master file, preserving assessment history.*

*   **Input Checklists**:
    *   **Base Checklist**: The most recent checklist (source of truth for current status).
    *   **History Files**: Add one or more older CKL files. The tool will import findings and comments from these files into the base checklist's history.
*   **Output**: Destination for the merged file.
*   **Options** *(hover for tooltips)*:
    *   **Preserve full history**: Keep a record of previous statuses and comments.
    *   **Apply boilerplates**: Fill empty findings with templates.
*   **Safety**: A **confirmation dialog** prevents accidental overwriting of existing output files. The "Clear" button also asks for confirmation before removing all history files.
*   **Feedback**: After merge, a summary dialog shows updated/unchanged VID counts.

### 3. 🔧 Extract Fixes
*Generate remediation scripts from the STIG benchmark.*

*   **Input & Output**:
    *   **XCCDF File**: The source benchmark containing fix text.
    *   **Output Dir**: Directory to save generated scripts.
*   **Export Formats**:
    *   Select desired formats: JSON, CSV, Bash (Linux), PowerShell (Windows).
*   **Options**:
    *   **Dry run mode**: Generate scripts that only print commands without executing them (safer for testing).

### 4. 📥 Import Results
*Apply automated scan results to your checklist.*

*   **Batch Import**:
    *   Add multiple JSON result files (from automated scanners) to process them in bulk.
*   **Single File Import**:
    *   Select a specific JSON result file.
*   **Target & Output**:
    *   **Target CKL**: The checklist to update.
    *   **Output CKL**: The updated checklist file.
*   **Options** *(hover for tooltips)*:
    *   **Auto-mark NotAFinding**: Automatically set status to "NotAFinding" if the scan result is "pass".
    *   **Dry run**: Preview changes without writing the output file.

### 5. 📎 Evidence Manager
*Manage evidence files (screenshots, logs) associated with specific vulnerabilities.*

*   **Import Evidence**:
    *   **Vuln ID**: Enter the V-ID (e.g., V-12345).
    *   **Description**: Brief note about the evidence.
    *   **Select & Import**: Choose the file to attach.
*   **Export / Package**:
    *   **Export All**: Save all evidence files to a folder.
    *   **Create Package**: Zip all evidence for transfer.
    *   **Import Package**: Import a zip of evidence files.

### 6. ✅ Validate
*Check if a CKL file is valid and compatible with STIG Viewer 2.18.*

*   **Checklist (CKL)**: Select the file to validate.
*   **Validate Button**: Runs checks and displays a **color-coded** report highlighting:
    *   🔴 **Errors** (red, bold) — Critical issues preventing use
    *   🟡 **Warnings** (amber) — Non-critical issues
    *   🟢 **Results** (green, bold) — Pass/fail summary
    *   🔵 **Information** (blue) — Statistics

---

## 🛡️ Safety Features

*   **Overwrite Protection**: Output files prompt for confirmation before overwriting.
*   **Clear Confirmation**: Clearing file lists requires confirmation to prevent accidental data loss.
*   **Button Locking**: Action buttons are disabled during processing to prevent double-execution.
*   **Progress Indicator**: An animated progress bar shows during all long-running operations.

---

## 💡 Tips

*   **Presets**: Use **File > Save Preset** to save your current configuration (paths, asset details) so you can quickly reload them later. Use **File > Delete Preset** to remove old presets.
*   **Keyboard Shortcuts**:
    *   `Ctrl+S`: Save Preset
    *   `Ctrl+O`: Load Preset
    *   `Ctrl+Q`: Exit
*   **Tooltips**: Hover over checkboxes and options for detailed explanations.
*   **Status Icons**: The status bar uses icons like ✔ (Success) and ✘ (Error) for quick visual cues.

---

## 🖥️ CLI-Only Features

The following features are available exclusively through the command-line interface:

| Feature | Command | Description |
|---------|---------|-------------|
| **Compare Checklists** | `--diff CKL1 CKL2` | Compare two checklists and identify status/severity/content differences |
| **Repair Checklist** | `--repair FILE --repair-out FILE` | Fix common CKL corruption issues (invalid status, missing fields, oversized content) |
| **Compliance Stats** | `--stats FILE` | Generate compliance statistics (completion %, severity breakdown) |
| **Batch Convert** | `--batch-convert DIR` | Convert all XCCDF files in a directory to CKL format |
| **Verify Integrity** | `--verify-integrity FILE` | Compute SHA256 checksum and run full validation |
| **Compute Checksum** | `--compute-checksum FILE` | Display SHA256 hash for a file |

Run `python -m stig_assessor --help` for full CLI documentation with usage examples.
