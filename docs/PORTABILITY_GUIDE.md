# STIG Assessor Portability Guide

This guide details how to build and deploy STIG Assessor for entirely air-gapped or restricted environments. We provide two distinct portability paths depending on your endpoint restrictions and auditing requirements.

## Comparison of Portability Options

| **Option** | **Target OS** | **Dependencies** | **Auditability** | **Best For** |
| :--- | :--- | :--- | :--- | :--- |
| **1. EXE** | Windows | **Zero.** Python included. | Low (Compiled) | Simple distribution |
| **2. Lean** | Win/Linux | Python 3.9+ (System) | **High (Source)** | Auditable system Python |
| **3. Full** | Win/Linux | **Zero.** (Bundled 3.12) | **High (Source)** | Zero-dependency source |

---

## Option 1: The Compiled Binary (.exe)

By leveraging PyInstaller, the entirety of the STIG Assessor project—including the Python 3 interpreter, graphics libraries, and all internal web assets—is compiled into a single `STIG_Assessor.exe` binary.

### 1. How to Build

1. Open PowerShell in the `STIG_Script` directory.
2. Run the automated build script:

   ```powershell
   .\build_portable.ps1
   ```

3. Your portable executable will be created at: `.\dist\STIG_Assessor.exe`

### 2. Usage

- **GUI**: `.\STIG_Assessor.exe --gui`
- **Web**: `.\STIG_Assessor.exe --web`
- **CLI**: `.\STIG_Assessor.exe --batch-convert "C:\STIGs" ...`

---

## Option 2: The Portable Script Package

This option keeps the project entirely in Python and PowerShell/Bash scripts. This is ideal for cross-platform (Linux) support and environments where security policies require source-code auditing.

### 1. How to Prepare the Package (with Dependencies)

To ensure the script package is "completely portable" and works without an internet connection, use the bundling script on a machine with internet access:

1. Open PowerShell in the `STIG_Script` directory.
2. Run the script bundler:

   ```powershell
   .\scripts\bundle_scripts.ps1
   ```

3. This creates a folder at `.\dist\STIG_Assessor_Scripts\` containing:
   - The `stig_assessor` source code.
   - `launch.ps1` (Universal Windows/Linux PowerShell launcher).
   - `launch.sh` (Linux Bash launcher).
   - `lib/` (Vendored premium dependencies for immediate use).
   - `wheels/` (Offline installers for `venv` creation).

### 2. Usage on Target (Air-Gapped)

Copy the `STIG_Assessor_Scripts` folder to your target machine.

#### **On Windows (PowerShell)**

```powershell
.\launch.ps1          # Launches GUI
.\launch.ps1 -Mode web # Launches Web
```

#### **On Linux (Bash)**

```bash
./launch.sh           # Launches GUI
./launch.sh web       # Launches Web
```

#### **Direct Python Execution**

If you prefer to bypass the launchers:

```bash
export PYTHONPATH="./lib:$PYTHONPATH"  # Add vendored deps
python3 -m stig_assessor.ui.cli --gui
```

---

## Troubleshooting & Restriction Workarounds

### AppLocker blocks EXE extraction to %TEMP%

If your organization blocks executables from `%TEMP%`, **Option 2 (Scripts)** is the recommended solution as it runs directly from the source folder without unpacking.

### No Python/Dependencies on Target Host

If the target machine lacks Python or required libraries:

#### **Method A: The "Full" Bundle**
Download a "Windows embeddable package (64-bit)" (Python 3.12 recommended) and extract it into a folder named `python` or `python312` inside the script package. `launch.ps1` will prioritize this local interpreter.

#### **Method B: The "Lean" Venv (Automatic)**
If a system Python is found but libraries are missing, the launcher will detect the `wheels/` directory and offer to create a local `venv` and install all dependencies offline—no internet required.
