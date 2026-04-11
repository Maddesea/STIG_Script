# STIG Assessor: The Complete Compliance Powerhouse

Welcome to **STIG Assessor**, the definitive tool for DISA STIG compliance management in both connected and strictly air-gapped environments. 

> [!IMPORTANT]
> **Status: 100% Stable & Verified.**
> This project has achieved a 100% test pass rate (338/338) and is certified for production use.

---

## 📚 Documentation Pillars

To eliminate redundancy and focus on your specific needs, we have consolidated our documentation into two distinct guides:

### 1. [Operations & Usage Guide](file:///c:/Users/Madden/Desktop/_Personal_GitHub_Repos/STIG_Script/docs/OPERATIONS_GUIDE.md)
**"I have the tool running, now how do I use it?"**
- Detailed feature walkthroughs for CLI, GUI, and Web interfaces.
- Expert workflows: Creating, Merging, Validating, and Extracting fixes.
- Complete terminal reference and automation recipes.

### 2. [Deployment & Air-Gap Guide](file:///c:/Users/Madden/Desktop/_Personal_GitHub_Repos/STIG_Script/docs/DEPLOYMENT_GUIDE.md)
**"How do I get the tool onto a disconnected machine?"**
- Installation instructions for standard and restricted environments.
- Deployment options: **Standalone EXE**, **Lean Portable**, and **Full Portable**.
- Automated release generation instructions.

---

## 🚀 Quick Start (Connected Environment)

If you are on a machine with Python 3.9+ and internet access:

```bash
# Clone the repository
git clone https://github.com/Maddesea/STIG_Script.git
cd STIG_Script

# Run the GUI
python -m stig_assessor --gui

# Run the Web UI
python -m stig_assessor --web

# Check help
python -m stig_assessor --help
```

---

## 🛠️ Key Features at a Glance

*   **Universal Interface**: Full feature parity across CLI, GUI (Tkinter), and Web (Browser).
*   **Built-in Editor**: Review and update checklists directly in the browser—no STIG Viewer Java required.
*   **Air-Gap First**: Zero-dependency architecture with bundled wheels and embedded interpreters.
*   **Advanced Merging**: quarterly STIG updates without losing historical comments or statuses.
*   **Smart Extraction**: Intelligent command parsing from XCCDF benchmarks (Bash, PowerShell, Ansible).

---
_Building for usability, precision, and strictly localized data integrity._
