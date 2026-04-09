# STIG Assessor User Manual

Welcome to **STIG Assessor**, a comprehensive, air-gapped utility designed to streamline the assessment, remediation, and management of DISA STIG compliance protocols. The tool offers both a native Tkinter desktop interface and a modern, feature-rich Web application.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Using the Web Interface](#using-the-web-interface)
3. [Interactive Assessment Editor](#interactive-assessment-editor)
4. [Using the Desktop UI (Tkinter)](#using-the-desktop-ui-tkinter)
5. [Key Workflows](#key-workflows)

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

The Web UI provides a fast, polished, and dynamic environment for managing checklists. Upon launching the web app (`--web`), open your browser to the URL displayed in the console (usually `http://127.0.0.1:5000`).

### Navigating the Sidebar
*   **Create CKL:** Upload any DISA XCCDF Benchmark to automatically generate a prefilled `.ckl` file for asset management.
*   **Remediate:** Use SCAP or local scanner JSON outputs to automatically pre-fill checklist statuses based on scan results.
*   **Assessment Editor:** Engage directly with `.ckl` files to modify statuses, findings, and comments inside your browser. No Java viewer is required.
*   **Analytics & Dashboard:** Generate visual charts, compliance percentages, and severity breakdowns for a single checklist or an entire fleet.
*   **Bulk Operations:** Perform fast, wide-ranging edits over a checklist using regex combinations.

---

## Interactive Assessment Editor

A highly requested feature, the **Assessment Editor** lets you interact entirely with your checklist natively.

### Step-by-Step Interactive Editing:
1.  Navigate to **Assessment Editor** in the side navigation panel.
2.  Click **Upload Checklist to Edit** and supply your existing `.ckl` file.
3.  The system will analyze and cache all vulnerability findings, displaying them neatly sorted on the left pane.
4.  Use the **Search Bar** to instantly filter V-ids or Statuses (e.g., "Not_Reviewed" or "V-12345").
5.  Click on any vulnerability to populate the detailed viewing window. Here, you can review the exact `Check Content` and `Fix Text`.
6.  Adjust the **Status**, **Finding Details**, and **Comments**.
7.  Click **Save Changes**. The UI will flash to dynamically reflect your modifications.
8.  When complete, click the **Download Updated CKL** button at the bottom of the interface to securely store your modifications locally.

---

## Using the Desktop UI (Tkinter)

In fully locked-down environments, the Tkinter UI is exceptionally lightweight and guarantees operability standard to native desktop OS themes.

The GUI mirrors the capability of the web app using a standard Tabular layout. Highlights include:
*   **Premium Color Palettes**: Switch effortlessly between streamlined Dark Mode and Light Mode with a built-in theme toggle to reduce eye strain.
*   **Keyboard Accessibility**: Execute tab transitions via explicit mappings.
*   **Decoupled processing**: Prevents the UI from locking up when analyzing heavy configuration audits.

---

## Key Workflows

### 1. Generating a New Assessment
1. Determine your required platform STIG (XCCDF format) from DISA's Cyber Exchange.
2. Navigate to **Create CKL**.
3. Upload the `.xml` file alongside asset metadata (IP, MAC, Role).
4. Download the finalized, structural `.ckl` instantly.

### 2. Fleet Compliance Roll-Up
1. Create a standard `.zip` containing up to hundreds of completed `.ckl` files.
2. Navigate to **Fleet Analytics**.
3. Upload the archive. The program maps compliance levels across the enclave, offering an overarching compliance score and specific data matrices.

### 3. Drift Analysis (Tracking Changes)
1. Use the **Ingest/Track CKL** module to cache a baseline assessment into the local SQLite `history` database.
2. Upload a newer checklist at a later date.
3. Run the **Drift Analysis**. The platform outputs exact metrics demonstrating resolved vulns alongside regressions, allowing assessors to pinpoint configuration drifts efficiently.

---
_Built for usability, precision, and strictly localized data integrity._
