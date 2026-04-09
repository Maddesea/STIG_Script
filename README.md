# STIG Assessor: The Complete A-to-Z User Guide

Welcome to the definitive user guide for **STIG Assessor** (v8.1.0 Modular Edition). This document serves as your single source of truth for expertly running STIG Assessor, whether you are using the modern Graphical User Interface (GUI) or the highly scriptable Command Line Interface (CLI).

STIG Assessor simplifies DISA STIG (Security Technical Implementation Guide) compliance tracking, remediation extraction, and continuous checklist management.

> **📖 Comprehensive Reference:** See [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) for the full 1,400+ line manual covering every feature, command, API endpoint, and automation recipe across CLI, GUI, and Web interfaces.

---

## Table of Contents

1. [Installation & Security Prerequisites](#1-installation--security-prerequisites)
2. [The A-to-Z Workflow Overview](#2-the-a-to-z-workflow-overview)
3. [Phase A: Creating Your First Checklist](#3-phase-a-creating-your-first-checklist)
4. [Phase B: Managing Evidence](#4-phase-b-managing-evidence)
5. [Phase C: Extracting & Executing Fixes](#5-phase-c-extracting--executing-fixes)
6. [Phase D: Applying Automated Remediation Results](#6-phase-d-applying-automated-remediation-results)
7. [Phase E: Merging & Updating Checklists](#7-phase-e-merging--updating-checklists)
8. [Phase F: Validation, Repair, and Compliance Stats](#8-phase-f-validation-repair-and-compliance-stats)
9. [Advanced: Batch Operations & Diffing Checklists](#9-advanced-batch-operations--diffing-checklists)

---

## 1. Installation & Security Prerequisites

STIG Assessor has a zero-dependency goal for high-side/air-gapped environments, but highly recommends `defusedxml` to protect against XML-based attacks (like XXE or Billion Laughs) when parsing untrusted XCCDF benchmarks from external sources.

**Recommended Setup:**
```bash
# Secure XML parsing (Strongly Recommended for DoD)
pip install defusedxml

# GUI Support (Required if using --gui on Linux)
sudo apt install python3-tk
```

**Starting the Application:**
You can interact with STIG Assessor via the `stig_assessor` module:
```bash
python3 -m stig_assessor.ui.cli --gui   # Launch the Graphical Interface
python3 -m stig_assessor.ui.cli --help  # View CLI help and commands
```

---

## 2. The A-to-Z Workflow Overview

Achieving compliance expertly involves moving through a standard lifecycle:

1. **Create:** Convert raw `XCCDF` benchmarks provided by DISA into STIG Viewer-compatible `.ckl` checklists.
2. **Track:** Attach evidence (screenshots, logs) to findings.
3. **Remediate:** Extract predefined fixes (Bash/PowerShell/JSON) from the XCCDF, execute them, and automatically log the success parameters via automated scans.
4. **Merge & Preserve:** Carry forward comments, history, and status markings from old checklists onto newly released STIG versions.
5. **Validate:** Periodically validate the `.ckl` file to proactively prevent STIG Viewer corruption, generate statistics, and finalize.

---

## 3. Phase A: Creating Your First Checklist

The first step is transforming an `.xml` XCCDF Benchmark into a usable STIG `CKL` format. 

### 🖥️ GUI Method
1. Launch the GUI: `python3 -m stig_assessor.ui.cli --gui`
2. Go to the **Create CKL** tab.
3. Select your `.xml` XCCDF file and specify where to output the `.ckl`.
4. Enter your system metadata: Asset Name (Hostname), IP, MAC, and Marking (e.g., CUI).
5. *(Optional)* Check **Apply Boilerplate** to immediately prepopulate blank findings with default organizational standards.
6. Click **Create CKL**.

### 💻 CLI Method
```bash
python3 -m stig_assessor.ui.cli --create \
  --xccdf rhel8_stig.xml \
  --asset "SERVER-01" \
  --ip "192.168.1.100" \
  --role "Web Server" \
  --marking "CUI" \
  --apply-boilerplate \
  --out server01_baseline.ckl
```
*Note: Include `--dry-run` to test the operation without writing files to disk.*

---

## 4. Phase B: Managing Evidence

For each finding, you will often need to maintain screenshots, text logs, and other auditing artifacts. STIG Assessor includes an **Evidence Manager** that uses content-based deduplication and zipping.

### 🖥️ GUI Method
1. Navigate to the **Evidence Manager** tab.
2. Enter the target `V-ID` (e.g., V-123456).
3. Provide a brief description and use **Select & Import** to attach a file.
4. To move evidence between teams or environments, use **Create Package** to export a deduplicated zip of all attachments.

### 💻 CLI Method
```bash
# Import a file for a specific vulnerability
python3 -m stig_assessor.ui.cli --import-evidence "V-123456" screenshot.png \
  --evidence-desc "Firewall status showing drop rules" \
  --evidence-cat "config"

# Create a zip package for auditors or offline transfer
python3 -m stig_assessor.ui.cli --package-evidence complete_evidence.zip
```

---

## 5. Phase C: Extracting & Executing Fixes

STIGs contain embedded remediation logic. You can extract these into ready-to-use Bash or PowerShell scripts instead of manually transcribing them.

### 🖥️ GUI Method
1. Select the **Extract Fixes** tab.
2. Input the source XCCDF file.
3. Select an output directory.
4. Toggle on output formats (`Bash (Linux)`, `PowerShell (Windows)`, `JSON`, `CSV`).
5. Click **Extract Fixes**. (Check *Dry run mode* to generate scripts that only print commands rather than mutating system state).

### 💻 CLI Method
```bash
python3 -m stig_assessor.ui.cli --extract rhel8_stig.xml \
  --outdir ./fixes_dir \
  --no-json \
  --script-dry-run  # Output scripts will contain 'echo' checks rather than executing changes.
```

---

## 6. Phase D: Applying Automated Remediation Results

After running your generated scripts, Ansible playbooks, or third-party scanners, STIG Assessor can bulk-apply the answers directly to your `.ckl`. This removes the need for manual data entry.

### Part 1: Generating the Results JSON
Use the bundled `generate_remediation.py` wizard:
```bash
# Launch interactive wizard
python3 generate_remediation.py

# Or convert a CSV report into the required JSON array
python3 generate_remediation.py --from-csv results.csv --output results.json
```

### Part 2: Applying the Results
### 🖥️ GUI Method
1. Go to the **Import Results** tab.
2. Under "Batch Import" or "Single File," add your `results.json`.
3. Target your working `CKL` and define the output `CKL`.
4. Ensure **Auto-mark NotAFinding** is ticked so successful fixes update the checklist status.
5. Click **Import**.

### 💻 CLI Method
```bash
python3 -m stig_assessor.ui.cli --apply-results results.json \
  --checklist server01_baseline.ckl \
  --results-out server01_updated.ckl \
  --results-dry-run
```

---

## 7. Phase E: Merging & Updating Checklists

When DISA releases a new quarterly STIG update, you must convert your existing checklist logic to the new baseline without losing all your historical notes, comments, and severity overrides.

### 🖥️ GUI Method
1. Head to the **Merge Checklists** tab.
2. **Base Checklist**: The newest, blank CKL generated from the new quarterly XCCDF.
3. **History Files**: Add your old CKL files (can process multiple files in chronological order).
4. Click **Merge**.

### 💻 CLI Method
```bash
python3 -m stig_assessor.ui.cli --merge \
  --base q3_blank_baseline.ckl \
  --histories q1_assessment.ckl q2_assessment.ckl \
  --merge-out q3_preserved_assessment.ckl
```

---

## 8. Phase F: Validation, Repair, and Compliance Stats

Checklists often become organically corrupted by bad parsing tools, special string characters, or manual XML edit errors, failing to open in DISA STIG Viewer 2.18+.

### Validation & Stats (GUI)
- Open the **Validate** tab, select the checklist, and run. You receive a color-coded analysis showing `errors`, `warnings`, and overall checklist `statistics`.

### Validation & Repair (CLI)
```bash
# Validate if a Checklist is fully STIG Viewer 2.18 compatible
python3 -m stig_assessor.ui.cli --validate assessment.ckl

# Automatically strip bad XML characters and repair missing nodes
python3 -m stig_assessor.ui.cli --repair corrupt_assessment.ckl --repair-out fixed.ckl

# Print compliance statistics text to console (Completion %, Open, NaF)
python3 -m stig_assessor.ui.cli --stats assessment.ckl --stats-format text 
```

---

## 9. Advanced: Batch Operations & Diffing Checklists

For administrators managing fleet-wide operations, CLI-only advanced features act as powerful force multipliers.

**Batch XCCDF to CKL Generation:**
Point it at a folder to rapidly auto-convert dozens of `.xml`s simultaneously.
```bash
python3 -m stig_assessor.ui.cli --batch-convert ./disa_stig_folder \
  --batch-out ./ckl_out \
  --batch-asset-prefix "WIN10-"
```

**Checklist Diffing:**
Compare two checklist assessments to see exactly what changed regarding status boundaries, fix comments, or severity ratings.
```bash
python3 -m stig_assessor.ui.cli --diff prev_assessment.ckl current_assessment.ckl \
  --diff-format detailed
```

**Verify Integrity:**
```bash
# Ensures that checksums are valid and have not been tampered with
python3 -m stig_assessor.ui.cli --verify-integrity final_assessment.ckl
```

---

### End of Guide
Congratulations, you are now equipped to efficiently track STIG compliance utilizing STIG Assessor from end to end. Should you wish to orchestrate internal APIs directly using Python, please refer to the `API_DOCUMENTATION.md`.
