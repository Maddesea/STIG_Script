# STIG Assessor Portability Guide

This guide details how to build and deploy STIG Assessor for entirely air-gapped or restricted environments. We provide two distinct portability paths depending on your endpoint restrictions and auditing requirements.

## Comparison of Portability Options

| Feature | Option 1: Compiled Binary (.exe) | Option 2: Portable Script Package |
| :--- | :--- | :--- |
| **Target OS** | Windows Only | **Windows & Linux** |
| **Dependencies** | **Zero.** Python included in EXE. | Requires Python 3.9+ on target. |
| **Auditability** | Low (Compiled code) | **High (Source code visible)** |
| **Startup Speed** | Moderate (Unpacks to %TEMP%) | **Instant** |
| **File Format** | Single `.exe` file | Folder with `.py`, `.ps1`, `.sh` files |

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
   - `launch.ps1` (Windows/Linux PowerShell launcher).
   - `launch.sh` (Linux Bash launcher).
   - `lib/` (Vendored premium dependencies like `sv-ttk` for the premium UI).

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

### No Python on Target Windows Host

If you choose **Option 2** but the target machine lacks Python:

1. Download a "Windows embeddable package (64-bit)" from Python.org.
2. Extract it into a folder named `python` inside your script package.
3. `launch.ps1` will automatically detect and use this local Python interpreter instead of searching the system path.
