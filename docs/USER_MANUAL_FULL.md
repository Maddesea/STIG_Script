# STIG Assessor: Full Portability Manual (Zero-Dependency)

This manual details the five deployment options for STIG Assessor, each designed to be **completely portable** and zero-dependency in air-gapped or desktop-restricted environments.

---

## 🚀 Choosing Your Option

| Option | Entry Point | Target OS | Host Requirements | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **1. EXE** | `STIG_Assessor.exe` | Windows | **None** | Simple, single-file distribution. |
| **2. Lean** | `launch.ps1` / `.sh` | Win/Linux | **Python 3.9+** | Using system Python + bundled offline libraries. |
| **3. Windows Full** | `launch.ps1` | Windows | **None** | Auditable source code with bundled interpreter. |
| **4. Linux Full** | `launch.sh` | Linux | **None** | Zero-dependency Linux (x86_64) deployment. |

---

## 📂 Deployment Folders

Navigate to your `dist/` directory to find your ready-to-use packages:

### 1. Option 1: Compiled Executive (.EXE)
**Location:** `dist/STIG_Assessor_EXE/`
- **What's Inside**: A single `STIG_Assessor.exe` binary.
- **How to Use**: Double-click or run from CLI with `--gui`, `--web`, or `--help`.
- **Note**: This packs the entire environment inside the binary.

### 2. Option 2: Lean Portable (Venv + Wheels)
**Location:** `dist/STIG_Assessor_Lean_Portable/`
- **What's Inside**: Source code, launchers, and a `wheels/` folder.
- **How to Use**: Transfer to your host and run `.\launch.ps1` (Win) or `./launch.sh` (Linux).
- **Pro**: If no dependencies are found, the launcher will ask to create a local `venv` using your **system Python** and install the bundled offline libraries (`.whl`)—no internet required.
- **Why?**: This is the safest auditable option as it uses your own security-patched system Python.

### 3. Option 3: Windows Full Portable
**Location:** `dist/STIG_Assessor_Windows_Portable/`
- **What's Inside**: Bundled Python 3.12 interpreter, source, `lib/` (pre-installed), and `wheels/` (backup).
- **How to Use**: Run `.\launch.ps1`. It will prioritize the bundled `python/` folder.

### 4. Option 4: Linux Full Portable
**Location:** `dist/STIG_Assessor_Linux_Portable/`
- **What's Inside**: Bundled Linux Python binary, source, and `wheels/` (backup).
- **How to Use**: Transfer and run `./launch.sh`.

---

## 🛠️ Operational Guide

### Command Line Flags (All Options)
All options support the same arguments:
- `--gui`: Launches the standard desktop interface.
- `--web`: Launches the dash-boarded web interface (REST API).
- `--batch-convert <dir>`: Processes multiple XCCDF files in bulk.
- `--merge-base <ckl>`: Merges two checklists.

### Hybrid Setup (Zero-Internet)
The script-based options (`Lean` and `Full`) are designed to be hybrid:
1. They search for a local `venv/`.
2. They search for a bundled `python/` interpreter.
3. They search for a system Python.
4. If a system Python is found but libraries are missing, they use the bundled `wheels/` to configure the environment offline.

### Troubleshooting
- **Path Issues**: If moving the folder, ensure the entire directory structure is preserved.
- **Execution Policy (Windows)**: If `launch.ps1` is blocked, you can run:
  `powershell -ExecutionPolicy Bypass -File .\launch.ps1`.
- **Permissions (Linux)**: Ensure the launcher and the bundled python have execution permissions:
  `chmod +x launch.sh python/bin/python3`.
