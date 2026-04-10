# STIG Assessor User Manual

Welcome to **STIG Assessor**, a comprehensive, air-gapped utility designed to streamline the assessment, remediation, and management of DISA STIG compliance protocols. The tool offers both a native Tkinter desktop interface and a modern, feature-rich Web application.

---

## 🚀 Key Advanced Features (Phase 8+)

### 🔍 Advanced Filtering & Regex

Across the **Merge**, **Extraction**, and **Boilerplate** modules, you can now use powerful filtering logic to target specific vulnerabilities:

*   **VID Include/Exclude (Regex):** Use standard regular expressions (e.g., `V-25\d+` to match all V-25000 series rules) to dynamically include or exclude items.
*   **Explicit VID Lists:** Provide a comma or space-separated list of exact Vulnerability IDs to perform surgical operations on just those items.
*   **Status & Severity Multi-Select:** Filter operations by any combination of checklist statuses (Open, Not_Reviewed, etc.) and CAT I/II/III severities.

### 📅 Date-Aware Boilerplate Management

When applying boilerplate templates to a checklist, you can now specify a **Date Override**. 

*   This ensures all finding details and comments are timestamped with the actual assessment date rather than just the template creation date.
*   The UI includes a quick "📅 Today" button to instantly sync to the current system date.

### 🛠️ Rich Metadata Fix Extraction

The **Extract Fixes** engine now pulls deep technical context from XCCDF benchmarks:

*   **Rich Data:** Now extracts "Discussion," "Mitigation," "Check Text," and "False Positives."
*   **Interactive HTML Playbooks:** Generating an HTML report now creates a premium, accordion-style remediation guide. Each finding can be expanded to view check logic, fix scripts, and technical discussion in a clean, readable format.

---

## Getting Started

### Prerequisites

STIG Assessor is designed with zero internal dependencies and relies entirely on standard Python 3.9+ libraries.

### Launching the Application

You can easily launch the tool using the CLI execution wrappers provided:

*   **Launch GUI Desktop App:** `python -m stig_assessor.main --gui`
*   **Launch Premium Web App:** `python -m stig_assessor.main --web`
    *(The web interface runs locally and does not require internet access).*

---

## Using the Web Interface

The Web UI provides a fast, polished, and dynamic environment for managing checklists. Upon launching the web app (`--web`), open your browser to `http://127.0.0.1:5000`.

### Core Workflows

*   **Generate CKL:** Upload any DISA XCCDF Benchmark to automatically generate a prefilled `.ckl` file. Enable "Apply boilerplates" to pre-populate finding details.
*   **Extract Fixes:** Pull Bash, PowerShell, or Ansible scripts from benchmarks. Use the **Preview** grid to surgically select exactly which fixes to export.
*   **Apply Results:** Import SCAP or results JSON outputs to automatically fill checklist statuses.
*   **Merge Checklists:** Combine historical checklists with granular control over which fields (Status, Details, Comments) are preserved or overwritten.

---

## Interactive Assessment Editor

The **Assessment Editor** lets you review and update your checklist natively in the browser—no Java STIG Viewer required.

1.  Navigate to **Assessment Editor** and upload your `.ckl` file.
2.  Use the **Search Bar** or **Filters** to find specific rules.
3.  Click on a vulnerability to view its **Check Content**, **Fix Text**, and even a **Rapid Remediation Script** preview.
4.  Update the **Status**, **Finding Details**, and **Comments**, then click **Save Changes**.
5.  Click **Download Updated CKL** at the bottom to save your work.

---

## Using the Desktop UI (Tkinter)

In fully locked-down environments, the Tkinter UI is exceptionally lightweight and guarantees operability standard to native desktop OS themes.

The GUI mirrors the capability of the web app with a tabular layout. Highlights include:
*   **Theme Toggle**: Switch between Dark Mode and Light Mode to reduce eye strain.
*   **Decoupled processing**: High-performance layout ensures the UI stays responsive during heavy analysis.

---

## Key Workflows

### 1. Advanced Merging with History

When merging checklists, use the **Advanced Merge Options** to:

*   Preserve full assessment history.
*   Filter by VID regex or status.
*   Configure conflict resolution (e.g., "Prefer Most Assessed").

### 2. Fleet Compliance Roll-Up

1. Create a `.zip` containing multiple `.ckl` files.
2. Upload to **Fleet Dashboard**.
3. View aggregated compliance scores, asset breakdowns, and cross-enclave statistics.

### 3. Drift Analysis (Tracking Changes)

1. Use **Ingest/Track CKL** to baseline an assessment in the history database.
2. Upload a newer checklist at a later date.
3. Run **Drift Analysis** to identify resolved vulnerabilities and regressions.

---
_Built for usability, precision, and strictly localized data integrity._
