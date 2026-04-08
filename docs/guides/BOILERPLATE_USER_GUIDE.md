# STIG Assessor — Boilerplate Templates: Complete User Guide

> **Version**: 8.1.0 | **Last Updated**: 2026-04-07 | **Environment**: Air-Gapped / Zero Dependencies

---

## Table of Contents

1. [Overview](#1-overview)
2. [Core Concepts](#2-core-concepts)
3. [Template Structure (JSON)](#3-template-structure-json)
4. [Template Variables](#4-template-variables)
5. [CLI Reference](#5-cli-reference)
6. [GUI Guide](#6-gui-guide)
7. [Web Interface Guide](#7-web-interface-guide)
8. [REST API Reference](#8-rest-api-reference)
9. [Apply Modes](#9-apply-modes)
10. [Import & Export Workflows](#10-import--export-workflows)
11. [Advanced Usage Patterns](#11-advanced-usage-patterns)
12. [Troubleshooting & FAQ](#12-troubleshooting--faq)

---

## 1. Overview

**Boilerplate templates** are pre-written text fragments for two CKL fields:

| Field             | Description                                        | Max Length |
|-------------------|----------------------------------------------------|-----------|
| `finding_details` | Technical explanation of the finding state          | 65,000    |
| `comments`        | Review notes, justifications, or auditor commentary | 32,000    |

Templates are organized by **Vulnerability ID (VID)** and **Status**, so you can prepare standard responses for every combination you encounter during assessment.

### When are boilerplates applied?

| Operation          | Trigger                                        | Default Mode     |
|--------------------|------------------------------------------------|------------------|
| `--create` / Generate CKL | `--apply-boilerplate` flag or GUI checkbox | `overwrite_empty` |
| `--merge`          | `--apply-boilerplate` flag                     | `overwrite_empty` |
| Bulk Operations    | Indirect (via template comments)               | N/A              |

### File Location

Boilerplates are stored in:
```
~/.stig_assessor/templates/boilerplate.json
```

This file is auto-created on first run with sensible defaults.

---

## 2. Core Concepts

### 2.1 VID Resolution (Wildcard Fallback)

Templates use a **two-tier resolution** system:

1. **Specific VID** — e.g., `V-12345` with status `NotAFinding`
2. **Global Wildcard** — `V-*` with status `NotAFinding`

When applying a boilerplate, the system first checks for a VID-specific template. If none exists, it falls back to the global `V-*` template for that status.

```
Lookup order:
  V-12345 → NotAFinding  →  found? → use it
                           not found? ↓
  V-*     → NotAFinding  →  found? → use it
                           not found? → no boilerplate applied
```

### 2.2 Statuses

STIG Viewer recognizes exactly four statuses (case-sensitive):

| Status            | Meaning                              |
|-------------------|--------------------------------------|
| `NotAFinding`     | The system satisfies the requirement |
| `Open`            | The system does not satisfy the requirement |
| `Not_Applicable`  | The requirement does not apply       |
| `Not_Reviewed`    | Assessment has not been completed    |

### 2.3 Apply Modes

When boilerplate is applied to a VULN element, the **apply mode** controls how template text interacts with any existing text:

| Mode             | Behavior                                                       |
|------------------|----------------------------------------------------------------|
| `overwrite_empty`| Only fills in fields that are currently empty (default)         |
| `prepend`        | Adds boilerplate text **before** existing content              |
| `append`         | Adds boilerplate text **after** existing content               |
| `merge`          | Combines existing text with boilerplate, separated by a divider|

---

## 3. Template Structure (JSON)

The `boilerplate.json` file uses this schema:

```json
{
  "V-*": {
    "NotAFinding": {
      "finding_details": "This control is satisfied. Evidence: {asset}",
      "comments": "Reviewed by automated script."
    },
    "Not_Applicable": {
      "finding_details": "This control does not apply because: [justification]",
      "comments": "Not applicable to {asset} configuration."
    },
    "Open": {
      "finding_details": "This control is not satisfied. Findings: [describe issue]",
      "comments": "Remediation pending for {asset}."
    }
  },
  "V-12345": {
    "NotAFinding": {
      "finding_details": "Firewall is configured with deny-all default policy.",
      "comments": "Verified via running config on {asset}."
    }
  }
}
```

### Schema

```
{
  "<VID>": {                         // "V-*" for global, "V-12345" for specific
    "<Status>": {                    // "NotAFinding", "Open", etc.
      "finding_details": "<string>", // Text for the Finding Details field
      "comments": "<string>"         // Text for the Comments field
    }
  }
}
```

### Rules

- VID keys must be strings. Use `V-*` for global defaults.
- Status keys must exactly match one of the four valid STIG statuses.
- Both `finding_details` and `comments` are required within each status entry.
- Template variable placeholders (e.g., `{asset}`) are optional.

---

## 4. Template Variables

Templates support Python-style placeholder variables that are automatically replaced at apply time:

| Variable     | Replaced With                      | Example Input      | Example Output                    |
|--------------|------------------------------------|--------------------|-----------------------------------|
| `{asset}`    | The asset hostname/identifier      | `WEBSERVER01`      | `"Evidence: WEBSERVER01"`         |
| `{severity}` | The vulnerability severity level   | `high`             | `"Severity: high"`               |

### Usage Example

```json
{
  "V-*": {
    "NotAFinding": {
      "finding_details": "Control is satisfied on {asset}. Severity: {severity}",
      "comments": "Assessed by STIG Assessor."
    }
  }
}
```

When applied to asset `DBSERVER02` with severity `medium`:
```
Finding Details: "Control is satisfied on DBSERVER02. Severity: medium"
Comments:        "Assessed by STIG Assessor."
```

> **Note:** If a variable placeholder is present in the template but no value is supplied, Python will raise a `KeyError`. The system gracefully handles this, but it's best to only use supported variables.

---

## 5. CLI Reference

### 5.1 Listing Boilerplates

**List all boilerplates:**
```bash
python -m stig_assessor --bp-list
```
Outputs the full `boilerplate.json` content as formatted JSON.

**List boilerplates for a specific VID:**
```bash
python -m stig_assessor --bp-list-vid V-12345
```

### 5.2 Setting / Creating Boilerplates

```bash
python -m stig_assessor --bp-set \
  --vid V-12345 \
  --status NotAFinding \
  --finding "Firewall policy verified via running config." \
  --comment "Reviewed by admin. Compliant."
```

**Arguments:**

| Flag        | Required | Description                    |
|-------------|----------|--------------------------------|
| `--vid`     | Yes      | Target VID (e.g., `V-12345`)  |
| `--status`  | Yes      | Target status                  |
| `--finding` | No       | Finding details text           |
| `--comment` | No       | Comments text                  |

**Set a global default:**
```bash
python -m stig_assessor --bp-set \
  --vid "V-*" \
  --status Open \
  --finding "This control is not satisfied. Issue: [describe]" \
  --comment "CAP pending."
```

### 5.3 Deleting Boilerplates

**Delete a specific status entry:**
```bash
python -m stig_assessor --bp-delete --vid V-12345 --status Open
```

**Delete all statuses for a VID:**
```bash
python -m stig_assessor --bp-delete --vid V-12345
```

### 5.4 Exporting Boilerplates

```bash
python -m stig_assessor --bp-export /path/to/my_boilerplates.json
```

This creates a standalone JSON file containing all current templates. Useful for:
- Sharing templates across team members
- Backing up before making changes
- Transferring to air-gapped systems via removable media

### 5.5 Importing Boilerplates

```bash
python -m stig_assessor --bp-import /path/to/shared_boilerplates.json
```

Imported templates are **merged** with existing ones:
- New VID/status entries are added.
- Existing entries with the same VID/status are **overwritten** by the import.

### 5.6 Cloning Boilerplates

```bash
python -m stig_assessor --bp-clone V-12345 V-67890
```

Copies all status templates from `V-12345` to `V-67890`. Useful when:
- A new STIG version renames/renumbers a check
- Multiple VIDs share the same finding response

### 5.7 Resetting to Defaults

```bash
python -m stig_assessor --bp-reset
```

> **⚠ Warning:** This deletes all custom boilerplates and restores factory defaults. This action cannot be undone. Export first if you need a backup.

### 5.8 Applying During CKL Generation

```bash
python -m stig_assessor --create \
  --xccdf benchmark.xml \
  --out checklist.ckl \
  --asset WEBSERVER01 \
  --apply-boilerplate
```

This creates a new CKL and fills in finding details and comments using boilerplate templates for each VULN element's status.

### 5.9 Applying During Merge

```bash
python -m stig_assessor --merge \
  --base current.ckl \
  --history old1.ckl old2.ckl \
  --out merged.ckl \
  --apply-boilerplate
```

During merging, boilerplate is applied only to findings that have empty finding details or comments (default `overwrite_empty` mode).

---

## 6. GUI Guide

### 6.1 Accessing the Boilerplate Editor

1. Launch the GUI: `python -m stig_assessor --gui`
2. Click the **📝 Boilerplates** tab in the navigation bar.

### 6.2 Interface Layout

The Boilerplates tab has a split-pane layout:

| Left Panel                     | Right Panel                           |
|-------------------------------|---------------------------------------|
| List of all VIDs with color-coded status indicators | Editor for the selected VID |
| **+ Add VID** button at bottom | Status dropdown selector              |
|                               | Finding Details text area              |
|                               | Comments text area                    |
|                               | **💾 Save** and **🗑 Delete** buttons |

### 6.3 Editing a Boilerplate

1. Click a VID in the left panel (e.g., `V-*`)
2. Select a **Status** from the dropdown (e.g., `NotAFinding`)
3. Edit the **Finding Details** and/or **Comments** text areas
4. Click **💾 Save**
5. A status bar message confirms: `"Saved boilerplate for V-* / NotAFinding"`

### 6.4 Adding a New VID

1. Click **+ Add VID** at the bottom of the left panel
2. Enter the VID (e.g., `V-12345`) in the dialog
3. The VID is added to the list and selected for editing
4. Fill in the status, finding details, and comments
5. Click **💾 Save**

### 6.5 Deleting a Boilerplate

1. Select the VID and status you want to delete
2. Click **🗑 Delete**
3. Confirm the deletion in the dialog

### 6.6 Import / Export via Menu

- **File → Export Boilerplates…** — Save all templates to a JSON file
- **File → Import Boilerplates…** — Load and merge templates from a JSON file

### 6.7 Applying During CKL Creation

On the **➕ Create Checklist** tab:
1. Check the **☐ Apply boilerplate templates** checkbox
2. Proceed with CKL generation as normal

This fills in finding details and comments for each VULN using the matching boilerplate template.

### 6.8 Settings Integration

Under **⚙ Settings**:
- Toggle **"Apply boilerplate by default"** to auto-check the boilerplate checkbox on every new CKL creation operation.

---

## 7. Web Interface Guide

### 7.1 Accessing the Boilerplate Editor

1. Start the web server: `python -m stig_assessor --web`
2. Open `http://localhost:8080` in your browser
3. Click **Boilerplates** in the sidebar under **Management**

### 7.2 Interface Layout

The Boilerplates panel consists of:

- **Toolbar** — `+ Add VID`, `⬇ Export`, `⬆ Import`, `↻ Reset Defaults` buttons
- **Left sidebar** — Searchable list of VIDs with status count badges
- **Right editor** — Form fields for editing the selected VID template

### 7.3 Editing a Boilerplate

1. Click a VID in the sidebar list (e.g., `V-*`)
2. The editor loads with the VID, first available status, and corresponding text
3. Change the **Status** dropdown to switch between status templates
4. Edit the **Finding Details** and **Comments** text areas
5. Click **Save**

### 7.4 Adding a New VID

1. Click **+ Add VID** in the toolbar
2. Enter the VID in the prompt dialog
3. The editor switches to the new VID with empty fields
4. Fill in status, finding details, and comments
5. Click **Save**

### 7.5 Export / Import

**Export:**
1. Click **⬇ Export** in the toolbar
2. A `boilerplates.json` file is downloaded to your browser

**Import:**
1. Click **⬆ Import** in the toolbar
2. Select a `.json` boilerplate file from your local filesystem
3. Imported templates are merged with existing ones
4. The sidebar refreshes to show any new VIDs

### 7.6 Reset to Defaults

1. Click **↻ Reset Defaults** in the toolbar
2. Confirm the action in the dialog
3. All custom templates are replaced with factory defaults

### 7.7 Template Variables Reference

At the bottom of the editor panel, a **📌 Template Variables** section shows available placeholders:
- `{asset}` — Asset hostname or identifier
- `{severity}` — Vulnerability severity level

Use these in your template text and they'll be substituted when boilerplate is applied during CKL generation.

---

## 8. REST API Reference

All endpoints accept `POST` with JSON body and return JSON responses.

### `POST /api/v1/bp_list`

List all boilerplate templates.

**Request:** `{}` (no parameters)

**Response:**
```json
{
  "status": "success",
  "data": {
    "V-*": {
      "NotAFinding": {
        "finding_details": "This control is satisfied.",
        "comments": "Reviewed."
      }
    }
  }
}
```

### `POST /api/v1/bp_set`

Create or update a boilerplate entry.

**Request:**
```json
{
  "vid": "V-12345",
  "status": "NotAFinding",
  "finding": "Firewall policy verified.",
  "comment": "Compliant as of 2026-04-07."
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Updated boilerplate for V-12345 / NotAFinding"
}
```

### `POST /api/v1/bp_delete`

Delete a specific boilerplate entry.

**Request:**
```json
{
  "vid": "V-12345",
  "status": "NotAFinding"
}
```

### `POST /api/v1/bp_export`

Export all boilerplates as a base64-encoded JSON file.

**Request:** `{}` (no parameters)

**Response:**
```json
{
  "status": "success",
  "data": {
    "bp_b64": "<base64-encoded JSON>"
  }
}
```

### `POST /api/v1/bp_import`

Import boilerplates from a base64-encoded JSON string. Merges with existing templates.

**Request:**
```json
{
  "bp_b64": "<base64-encoded JSON>"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Imported 5 VID template(s)"
}
```

### `POST /api/v1/bp_reset`

Reset all boilerplates to factory defaults.

**Request:** `{}` (no parameters)

**Response:**
```json
{
  "status": "success",
  "message": "Boilerplates reset to factory defaults"
}
```

---

## 9. Apply Modes

### 9.1 `overwrite_empty` (Default)

Only fills in finding details or comments when the field is currently empty. This is the safest mode — it never overwrites existing data.

**Use when:** Generating new CKLs or applying defaults to unreviewed findings.

### 9.2 `prepend`

Places the boilerplate text **before** any existing content, separated by a blank line.

**Result:**
```
[Boilerplate text]

[Existing text]
```

**Use when:** Adding a standard header or policy statement above manual notes.

### 9.3 `append`

Places the boilerplate text **after** any existing content, separated by a blank line.

**Result:**
```
[Existing text]

[Boilerplate text]
```

**Use when:** Adding standardized footer notes below manual assessments.

### 9.4 `merge`

Combines existing text with boilerplate, separated by a clear divider line.

**Result:**
```
[Existing text]
--- Boilerplate ---
[Boilerplate text]
```

**Use when:** You want both the original and template text clearly delineated for audit review.

---

## 10. Import & Export Workflows

### 10.1 Team Standardization Workflow

```
Team Lead                     Team Members
────────                     ────────────
1. Create standard templates
2. Export: --bp-export team_bp.json
3. Distribute via USB/share
                              4. Import: --bp-import team_bp.json
                              5. Customize per-VID as needed
```

### 10.2 Air-Gapped Transfer

Since STIG Assessor runs in air-gapped environments:

1. On the **connected system**: Create templates, export to JSON
2. Copy JSON file to removable media (USB drive)
3. On the **air-gapped system**: Import the JSON file
4. Templates are merged — existing templates are preserved unless overridden

### 10.3 Backup Before Changes

Before making bulk changes, always export:
```bash
python -m stig_assessor --bp-export backup_$(date +%Y%m%d).json
```

If something goes wrong:
```bash
python -m stig_assessor --bp-reset
python -m stig_assessor --bp-import backup_20260407.json
```

---

## 11. Advanced Usage Patterns

### 11.1 Per-VID Customization

Build a library of VID-specific responses for your organization's most common findings:

```bash
# Set specific templates for commonly assessed controls
python -m stig_assessor --bp-set --vid V-220813 --status NotAFinding \
  --finding "Password complexity requirements are configured via Group Policy. Minimum length: 15 characters, complexity enabled." \
  --comment "Verified via rsop.msc and secpol.msc on {asset}."

python -m stig_assessor --bp-set --vid V-220813 --status Open \
  --finding "Password complexity requirements are not configured per STIG requirements." \
  --comment "CAP submitted. Target remediation date: [DATE]."
```

### 11.2 Cloning for STIG Version Migration

When a new STIG version renumbers checks:
```bash
# Old check V-220813 is now V-254239 in the new STIG
python -m stig_assessor --bp-clone V-220813 V-254239
```

### 11.3 Multi-Status Templates via JSON

For complex setups, edit `boilerplate.json` directly:

```json
{
  "V-*": {
    "NotAFinding": {
      "finding_details": "This control is satisfied. Evidence collected from {asset}.",
      "comments": "Assessed via automated tooling."
    },
    "Open": {
      "finding_details": "Finding: [describe technical issue]",
      "comments": "POA&M tracking number: [enter POA&M ID]"
    },
    "Not_Applicable": {
      "finding_details": "This control is not applicable: [provide technical justification]",
      "comments": "N/A justification approved by ISSM."
    },
    "Not_Reviewed": {
      "finding_details": "Pending review. Scheduled assessment date: [DATE]",
      "comments": "Awaiting system access or documentation."
    }
  },
  "V-220813": {
    "NotAFinding": {
      "finding_details": "Password policy meets STIG requirements per GPO analysis.",
      "comments": "secedit output collected as evidence on {asset}."
    }
  }
}
```

### 11.4 Web API Scripting

Use `curl` or Python `requests` to manage boilerplates programmatically:

```bash
# List all boilerplates
curl -s -X POST http://localhost:8080/api/v1/bp_list \
  -H "Content-Type: application/json" -d '{}' | python -m json.tool

# Set a boilerplate
curl -s -X POST http://localhost:8080/api/v1/bp_set \
  -H "Content-Type: application/json" \
  -d '{"vid":"V-99999","status":"Open","finding":"Test finding","comment":"Test comment"}'
```

---

## 12. Troubleshooting & FAQ

### Q: My boilerplate wasn't applied to the CKL. Why?

**A:** Check these conditions:
1. Did you use `--apply-boilerplate` flag (CLI) or check the "Apply boilerplate" checkbox (GUI/Web)?
2. Does a matching template exist? The system resolves VID-specific first, then `V-*`.
3. Is the field already populated? By default, `overwrite_empty` mode only fills empty fields.
4. Is the status correct? Templates are status-specific — a `NotAFinding` template won't apply to an `Open` finding.

### Q: How do I see which variables are available?

**A:** Currently supported variables:
- `{asset}` — Replaced with the asset name provided during CKL generation
- `{severity}` — Replaced with the vulnerability severity level

In the Web UI, a **📌 Template Variables** reference is shown at the bottom of the editor panel.

### Q: Can I use HTML or special formatting in boilerplate text?

**A:** No. STIG Viewer treats finding details and comments as plain text. HTML tags will appear as literal text in the checklist.

### Q: What happens if I import a file with VIDs that already exist?

**A:** Import uses a **merge** strategy:
- New VID/status combinations are added.
- Existing VID/status combinations are **replaced** with the imported values.
- VIDs not present in the import file are preserved unchanged.

### Q: How do I use the same boilerplate for all 4 statuses?

**A:** You must create a separate template for each status. The system does not support a "universal" template that applies regardless of status.

### Q: I accidentally deleted all my templates. How do I recover?

**A:** If you have a backup:
```bash
python -m stig_assessor --bp-import backup.json
```
If not, reset to factory defaults:
```bash
python -m stig_assessor --bp-reset
```

### Q: Where is the boilerplate file stored?

**A:** `~/.stig_assessor/templates/boilerplate.json`

On Windows: `%USERPROFILE%\.stig_assessor\templates\boilerplate.json`

### Q: Can multiple users share the same boilerplate file?

**A:** The file is per-user by default. For team standardization:
1. One person creates the master template
2. Exports it: `--bp-export master_bp.json`
3. Distributes to team members
4. Each member imports: `--bp-import master_bp.json`

### Q: Is there a limit to how many boilerplates I can have?

**A:** No hard limit. However, the JSON file is loaded entirely into memory at startup, so keep it manageable. Thousands of VID-specific entries are fine; hundreds of thousands may impact startup time.

---

*This guide covers STIG Assessor v8.1.0 boilerplate functionality. For general tool usage, see the [main documentation](../guides/).*
