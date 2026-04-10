# STIG Assessor: Deployment & Portability Guide

This guide details how to install, build, and deploy STIG Assessor across standard, restricted, or entirely air-gapped environments. 

---

## 🚀 Choosing Your Deployment Option

We provide three primary distribution paths depending on your endpoint restrictions and auditing requirements.

| **Option** | **Target OS** | **Dependencies** | **Auditability** | **Best For** |
| :--- | :--- | :--- | :--- | :--- |
| **1. Standalone EXE** | Windows | **Zero.** Python included. | Low (Compiled) | Simple, single-file distribution |
| **2. Lean Portable** | Win/Linux | Python 3.9+ (System) | **High (Source)** | Using host-resident Python |
| **3. Full Portable** | Win/Linux | **Zero.** (Bundled 3.12) | **High (Source)** | Zero-dependency source |

---

## 📦 Automated Release Packaging

To ensure the highest level of stability and zero-dependency readiness, we provide a unified packaging script that generates all distribution formats automatically.

1. Open PowerShell in the root `STIG_Script` directory.
2. Run the release packager:
   ```powershell
   .\scripts\package_release.ps1
   ```
3. This creates a `dist/` directory containing your ready-to-use bundles:
   - `STIG_Assessor.exe`: Single standalone binary (Option 1).
   - `STIG_Assessor_Lean_Portable/`: Source code + offline wheels for host-resident Python (Option 2).
   - `STIG_Assessor_Full_Portable/`: Source code + internal pre-configured Python 3.12 (Option 3).

---

## 📂 Deployment & Usage on Target

Copy your preferred bundle from `dist/` to your target machine.

### **Launching the Application**

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

### **Hybrid Dependency Detection**
The launchers (`launch.ps1` and `launch.sh`) use a multi-stage search to ensure the tool runs regardless of the environment:
1. They prioritize a local virtual environment (`venv/`).
2. They search for a bundled interpreter (`python312/` or `python/`).
3. They search for a system-wide Python.
4. **Offline Auto-Harden**: If a system Python is found but libraries (`defusedxml`, `sv-ttk`) are missing, the launchers will detect the `wheels/` directory and offer to create a local `venv` and install the dependencies offline.

---

## 🛠️ Troubleshooting & Restrictions

### AppLocker blocks EXE extraction to %TEMP%
If your organization blocks executables from `%TEMP%`, **Option 2 or 3 (Portable Folders)** is the recommended solution as they run directly from the source folder without unpacking to temporary directories.

### No Python on Target Host
If the target machine lacks a Python installation entirely, use **Option 3 (Full Portable)**. The internal `python312` folder is pre-configured with all required dependencies and is automatically prioritized by the launchers.

### Permission Denied (Linux)
Ensure the launcher and the bundled python have execution permissions:
```bash
chmod +x launch.sh python312/python
```

### Execution Policy (Windows)
If `launch.ps1` is blocked by execution policy, run:
```powershell
powershell -ExecutionPolicy Bypass -File .\launch.ps1
```
