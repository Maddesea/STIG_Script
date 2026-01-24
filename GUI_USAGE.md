# STIG Assessor GUI Usage Guide

This guide provides detailed instructions on how to use the **STIG Assessor** graphical user interface (GUI). The GUI has been redesigned to improve usability, layout, and visual consistency.

## 🚀 Launching the GUI

To start the graphical interface, run the script with the `--gui` flag:

```bash
python3 STIG_Script.py --gui
```

*Note: Ensure you have `python3-tk` installed on your system.*

## 🖥️ Interface Overview

The interface is organized into logical tabs for different workflows.

*   **Global Status Bar**: Located at the very bottom of the window, this bar provides real-time feedback on operations (e.g., "Processing...", "Success", "Error").
*   **Menu Bar**:
    *   **File**: Save/Load presets, Exit.
    *   **Tools**: Import/Export history, Manage boilerplate templates, Cleanup old files.
    *   **Help**: Application information.

---

## 📑 Tab Guide

### 1. Create CKL
*Convert an XCCDF benchmark file into a STIG Viewer checklist (CKL).*

*   **Files Section**:
    *   **XCCDF File**: Browse for the source `.xml` benchmark file.
    *   **Output CKL**: Select where to save the generated checklist.
*   **Asset Details**:
    *   **Asset Name**: (Required) The hostname of the system being assessed.
    *   **IP / MAC**: Optional network details.
    *   **Marking**: Classification marking (e.g., CUI, PROPRIETARY).
    *   **Apply Boilerplate**: Check this to automatically populate findings with default templates.

### 2. Merge Checklists
*Combine multiple checklists into a single master file, preserving assessment history.*

*   **Input Checklists**:
    *   **Base Checklist**: The most recent checklist (source of truth for current status).
    *   **History Files**: Add one or more older CKL files. The tool will import findings and comments from these files into the base checklist's history.
*   **Output**: Destination for the merged file.
*   **Options**:
    *   **Preserve full history**: Keep a record of previous statuses and comments.
    *   **Apply boilerplates**: Fill empty findings with templates.

### 3. Extract Fixes
*Generate remediation scripts from the STIG benchmark.*

*   **Input & Output**:
    *   **XCCDF File**: The source benchmark containing fix text.
    *   **Output Dir**: Directory to save generated scripts.
*   **Export Formats**:
    *   Select desired formats: JSON, CSV, Bash (Linux), PowerShell (Windows).
*   **Options**:
    *   **Dry run mode**: Generate scripts that only print commands without executing them (safer for testing).

### 4. Import Results
*Apply automated scan results to your checklist.*

*   **Batch Import**:
    *   Add multiple JSON result files (from automated scanners) to process them in bulk.
*   **Single File Import**:
    *   Select a specific JSON result file.
*   **Target & Output**:
    *   **Target CKL**: The checklist to update.
    *   **Output CKL**: The updated checklist file.
*   **Options**:
    *   **Auto-mark NotAFinding**: Automatically set status to "NotAFinding" if the scan result is "pass".

### 5. Evidence Manager
*Manage evidence files (screenshots, logs) associated with specific vulnerabilities.*

*   **Import Evidence**:
    *   **Vuln ID**: Enter the V-ID (e.g., V-12345).
    *   **Description**: Brief note about the evidence.
    *   **Select & Import**: Choose the file to attach.
*   **Export / Package**:
    *   **Export All**: Save all evidence files to a folder.
    *   **Create Package**: Zip all evidence for transfer.
    *   **Import Package**: Import a zip of evidence files.

### 6. Validate
*Check if a CKL file is valid and compatible with STIG Viewer 2.18.*

*   **Checklist (CKL)**: Select the file to validate.
*   **Validate Button**: Runs checks and displays a report in the text area below, highlighting errors (red) and warnings (yellow).

---

## 💡 Tips

*   **Presets**: Use **File > Save Preset** to save your current configuration (paths, asset details) so you can quickly reload them later.
*   **Keyboard Shortcuts**:
    *   `Ctrl+S`: Save Preset
    *   `Ctrl+O`: Load Preset
    *   `Ctrl+Q`: Exit
*   **Status Icons**: The status bar uses icons like ✔ (Success) and ✘ (Error) for quick visual cues.
