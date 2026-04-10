# STIG Assessor Portability Guide

This guide details how to build and deploy STIG Assessor for entirely air-gapped or restricted environments. We provide two distinct portability paths depending on your endpoint restrictions and auditing requirements.

## Comparison of Portability Options

| **Option** | **Target OS** | **Dependencies** | **Auditability** | **Best For** |
| :--- | :--- | :--- | :--- | :--- |
| **1. EXE** | Windows | **Zero.** Python included. | Low (Compiled) | Simple distribution |
| **2. Lean** | Win/Linux | Python 3.9+ (System) | **High (Source)** | Auditable system Python |
| **3. Full** | Win/Linux | **Zero.** (Bundled 3.12) | **High (Source)** | Zero-dependency source |

---

3. Your portable executable will be created at: `.\dist\STIG_Assessor.exe`

---

## Automated Release Packaging (Recommended)

To ensure the highest level of stability and zero-dependency readiness, we provide a unified packaging script that generates all distribution formats automatically.

1. Open PowerShell in the root directory.
2. Run the release packager:
   ```powershell
   .\scripts\package_release.ps1
   ```
3. This creates a `dist/` directory containing:
   - `STIG_Assessor.exe`: Single standalone binary (Option 1).
   - `STIG_Assessor_Lean_Portable/`: Source code + offline wheels for host-resident Python (Option 2).
   - `STIG_Assessor_Full_Portable/`: Source code + internal pre-configured Python 3.12 (Option 3).

---

### 2. Usage

- **GUI**: `.\STIG_Assessor.exe --gui`
- **Web**: `.\STIG_Assessor.exe --web`
- **CLI**: `.\STIG_Assessor.exe --batch-convert "C:\STIGs" ...`

---

## 2. Usage on Target (Air-Gapped)

Copy your preferred bundle from `dist/` to your target machine.

#### **On Windows (PowerShell)**

```powershell
.\launch.ps1          # Launches GUI
.\launch.ps1 -Mode web # Launches Web
.\launch.ps1 -Mode cli -Arguments "--help"
```

#### **On Linux (Bash)**

```bash
./launch.sh           # Launches GUI
./launch.sh web       # Launches Web
./launch.sh cli --help
```

---

## Troubleshooting & Restriction Workarounds

### AppLocker blocks EXE extraction to %TEMP%

If your organization blocks executables from `%TEMP%`, **Option 2 or 3 (Portable Folders)** is the recommended solution as they run directly from the source folder without unpacking to temporary directories.

### No Python on Target Host

If the target machine lacks a Python installation entirely, use **Option 3 (Full Portable)**. The internal `python312` folder is pre-configured with all required dependencies and is prioritized by the launchers.

### Python Present but Dependencies Missing

If a system Python is found but libraries (`defusedxml`, `sv-ttk`) are missing, the **Lean Portable** launcher will detect the `wheels/` directory and offer to create a local `venv` and install all dependencies offline—no internet required.
