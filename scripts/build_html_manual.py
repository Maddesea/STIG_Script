import os
import markdown
import sys
from pathlib import Path

def build_html():
    base_dir = Path(__file__).parent.parent
    docs_dir = base_dir / "docs"
    
    # Read the markdown files
    operations_md = (docs_dir / "OPERATIONS_GUIDE.md").read_text(encoding="utf-8")
    deployment_md = (docs_dir / "DEPLOYMENT_GUIDE.md").read_text(encoding="utf-8")
    
    # Combine and add a ton of examples as requested
    advanced_examples = """
## 25. Advanced Deep-Dive Examples & Edge Cases

The following section provides highly detailed guidance and examples for every complex operation within STIG Assessor, ensuring you have comprehensive examples for every possible workflow.

### Example 1: Creating a Custom Profile with Highly Specific Classification
```bash
# Workflow: You are requested to scan an air-gapped classified environment where standard "SECRET" is not descriptive enough.
stig-assessor --create --xccdf win_server.xml \
  --asset "TS-SCI-NET-01" \
  --ip "192.168.100.5" \
  --mac "00:11:22:33:44:55" \
  --role "Domain Controller" \
  --marking "TOP SECRET//SCI//NOFORN" \
  --apply-boilerplate \
  --out classified_dc.ckl
```

### Example 2: Handling Completely Air-Gapped PowerShell Remediation
When running remediation on a machine with no network and strict execution policies:
```powershell
# 1. First, export the script from the Assessor (on your workstation)
stig-assessor --extract U_CIS_Ubuntu_20-04_V1R1_Manual-xccdf.xml --outdir cis_fixes

# 2. On the target Windows Server, bypass Execution Policy temporarily for a single script:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Remediate.ps1

# 3. Import the exact results back
stig-assessor --apply-results ./stig_results_T1241.json --checklist classified_dc.ckl --results-out classified_dc_updated.ckl
```

### Example 3: Full Bulk-Editing for System-Wide Changes
An auditor states that all CAT I and CAT II findings must have an additional comment stating they are covered by an external POAM.
```bash
# Update all CAT I (High)
stig-assessor --bulk-edit final_assessment.ckl \
  --filter-severity high \
  --apply-comment "Tracking POAM ID: POAM-2026-991" \
  --append-comment

# Update all CAT II (Medium)
stig-assessor --bulk-edit final_assessment.ckl \
  --filter-severity medium \
  --apply-comment "Tracking POAM ID: POAM-2026-991" \
  --append-comment
```

### Example 4: The Ultimate Merge Scenario with Fallbacks
When a massive update invalidates previous finding structures, ensure history is fully packed:
```bash
stig-assessor --merge \
  --base Q1_2026_BLANK.ckl \
  --histories Q4_2025.ckl Q3_2025.ckl \
  --merge-out Q1_2026_MIGRATED.ckl
```
This forces STIG Assessor to chronologically parse Q3 and Q4, selecting the most recent status, embedding the past comments, and writing them perfectly into Q1.

## 26. Air-Gapped Packaging & Dependencies Guide

The `STIG_Script` repository has been deliberately designed to be fully self-contained for deployment to heavily restricted, disconnected environments. We have pre-downloaded all recommended external dependencies into the `wheels/` directory within this project.

### Pre-Packaged Project Dependencies
Your repository contains the following optional, but recommended libraries pre-downloaded in `wheels/`:
- **`defusedxml`**: Hardens XML parsing against Billion Laughs (XXE) attacks. (Strongly recommended for DoD and high-side environments).
- **`sv_ttk`**: Provides the premium Sun Valley Dark/Light theme for the GUI.
- **`pyinstaller` (and its dependencies)**: Used by the PowerShell build script to compile the application into a standalone binary.

### Building the Standalone Executable (Windows)
We provide `build_portable.ps1`, which leverages PyInstaller to create a single `.exe` file containing Python and all STIG Assessor logic.
1. Copy the entire `STIG_Script` directory to your build machine.
2. Open PowerShell and run:
   ```powershell
   .\build_portable.ps1
   ```
3. The script will automatically detect if PyInstaller is missing and **will install it completely offline** by resolving packages from the `wheels/` folder.
4. The final standalone executable will be written to `dist/STIG_Assessor.exe`. 
5. You can now transport `STIG_Assessor.exe` to any Windows system without needing Python or any internet access.

### Manual Source Deployment (Linux / Windows)
If you prefer running from source in a disconnected environment:
1. Transfer the `STIG_Script` folder to the target system.
2. Install the recommended modules securely entirely offline using the local `wheels/` folder:
   ```bash
   pip install --no-index --find-links=wheels defusedxml sv-ttk
   ```
3. Run the application:
   ```bash
   python -m stig_assessor --gui
   ```
"""
    
    combined_md = f"""[TOC]

{operations_md}

---

{deployment_md}

---

{advanced_examples}
    """
    
    md_parser = markdown.Markdown(extensions=['toc', 'fenced_code', 'tables', 'admonition'])
    html_content = md_parser.convert(combined_md)
    
    # Beautiful CSS
    css = """
    :root {
        --bg-color: #0f172a;
        --card-bg: #1e293b;
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
        --accent: #3b82f6;
        --accent-hover: #60a5fa;
        --border-color: #334155;
        --sidebar-width: 300px;
    }
    
    * {
        box-sizing: border-box;
    }
    
    body {
        margin: 0;
        padding: 0;
        background-color: var(--bg-color);
        color: var(--text-main);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.6;
        display: flex;
    }
    
    /* Sidebar Navigation */
    .sidebar {
        width: var(--sidebar-width);
        position: fixed;
        top: 0;
        bottom: 0;
        left: 0;
        background-color: var(--card-bg);
        border-right: 1px solid var(--border-color);
        padding: 20px;
        overflow-y: auto;
        box-shadow: 4px 0 15px rgba(0,0,0,0.2);
    }
    
    .sidebar h2 {
        color: var(--accent);
        font-size: 1.2rem;
        margin-top: 0;
        border-bottom: 2px solid var(--border-color);
        padding-bottom: 10px;
    }
    
    .sidebar ul {
        list-style-type: none;
        padding-left: 0;
    }
    .sidebar ul ul {
        padding-left: 15px;
        border-left: 1px solid var(--border-color);
        margin-left: 5px;
    }
    .sidebar li {
        margin: 8px 0;
    }
    .sidebar a {
        color: var(--text-muted);
        text-decoration: none;
        font-size: 0.9rem;
        transition: color 0.2s, font-weight 0.2s;
    }
    .sidebar a:hover {
        color: var(--text-main);
        font-weight: 600;
    }
    
    /* Main Content */
    .main-content {
        margin-left: var(--sidebar-width);
        padding: 40px;
        max-width: 1000px;
        width: 100%;
    }
    
    /* Typography */
    h1, h2, h3, h4, h5 {
        color: var(--text-main);
        margin-top: 2em;
        margin-bottom: 0.5em;
    }
    
    h1 {
        font-size: 2.5em;
        background: -webkit-linear-gradient(120deg, #60a5fa, #3b82f6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        border-bottom: 2px solid var(--border-color);
        padding-bottom: 10px;
    }
    
    a {
        color: var(--accent);
        text-decoration: none;
    }
    
    a:hover {
        text-decoration: underline;
    }
    
    /* Tables */
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        background-color: var(--card-bg);
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    th, td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
    }
    
    th {
        background-color: rgba(255,255,255,0.05);
        font-weight: 600;
        color: var(--accent-hover);
    }
    
    tr:last-child td {
        border-bottom: none;
    }
    
    tr:hover {
        background-color: rgba(255,255,255,0.02);
    }
    
    /* Code Blocks */
    pre {
        background-color: #0d1117;
        padding: 20px;
        border-radius: 8px;
        overflow-x: auto;
        border: 1px solid var(--border-color);
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
    }
    
    code {
        font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
        background-color: rgba(255,255,255,0.1);
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 0.9em;
    }
    
    pre code {
        background-color: transparent;
        padding: 0;
        color: #e2e8f0;
    }
    
    /* Blockquotes & Admonitions */
    blockquote {
        border-left: 4px solid var(--accent);
        margin: 20px 0;
        padding: 15px 20px;
        background-color: var(--card-bg);
        border-radius: 0 8px 8px 0;
        color: var(--text-muted);
    }
    
    .admonition {
        background-color: var(--card-bg);
        border-left: 4px solid #f59e0b;
        padding: 15px;
        margin: 20px 0;
        border-radius: 0 8px 8px 0;
    }
    .admonition-title {
        font-weight: bold;
        color: #fbbf24;
        margin-top: 0;
        margin-bottom: 10px;
        text-transform: uppercase;
        font-size: 0.85em;
        letter-spacing: 0.05em;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
        body {
            flex-direction: column;
        }
        .sidebar {
            width: 100%;
            position: relative;
            border-right: none;
            border-bottom: 1px solid var(--border-color);
        }
        .main-content {
            margin-left: 0;
            padding: 20px;
        }
    }
    """
    
    # We'll extract the TOC from the generated HTML
    # python-markdown puts it in `<div class="toc">...</div>`
    import re
    toc_match = re.search(r'<div class="toc">.*?</div>', html_content, re.DOTALL)
    toc_html = toc_match.group(0) if toc_match else ""
    
    # Remove TOC from main content to place in sidebar
    main_html = html_content.replace(toc_html, "")
    
    # Add a custom title to the TOC
    toc_html = toc_html.replace('<div class="toc">', '<div class="toc">\n<h2>Navigation</h2>')
    
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STIG Assessor - Comprehensive User Manual</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="sidebar">
        {toc_html}
    </div>
    <div class="main-content">
        {main_html}
    </div>
</body>
</html>
"""
    
    out_path = docs_dir / "STIG_Assessor_User_Manual.html"
    out_path.write_text(full_html, encoding="utf-8")
    print(f"Successfully wrote HTML manual to {out_path}")

if __name__ == "__main__":
    build_html()
