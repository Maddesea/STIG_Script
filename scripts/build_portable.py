#!/usr/bin/env python3
"""Build a self-contained STIG Assessor portable distribution for Windows.

This script packages the STIG Assessor source code along with the Windows
launcher scripts into a ZIP file. It also attempts to download the Python
3.12 embeddable package for Windows so the result is a truly zero-dependency
portable application.
"""

import os
import shutil
import urllib.request
import zipfile
from pathlib import Path

# Configuration
VERSION = "8.1.0"
PYTHON_VERSION = "3.12.3"
PYTHON_URL = f"https://www.python.org/ftp/python/{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-amd64.zip"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = PROJECT_ROOT / "build_dist"
DIST_DIR = PROJECT_ROOT / "dist"
APP_NAME = f"STIG_Assessor_v{VERSION}_Portable"
STAGE_DIR = BUILD_DIR / APP_NAME


def clean_build():
    print("Cleaning build directories...")
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)


def copy_source():
    print(f"Copying source files to {STAGE_DIR.name}...")
    STAGE_DIR.mkdir(parents=True)

    # Copy core package
    shutil.copytree(
        PROJECT_ROOT / "stig_assessor",
        STAGE_DIR / "stig_assessor",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )

    # Copy launchers and docs
    files_to_copy = [
        "launch_gui.bat",
        "launch_web.bat",
        "launch.ps1",
        "STIG_Script.py",
        "README.md",
        "CLAUDE.md",
    ]

    for f in files_to_copy:
        src = PROJECT_ROOT / f
        if src.exists():
            shutil.copy2(src, STAGE_DIR / f)
        else:
            print(f"  Warning: {f} not found, skipping.")


def download_python():
    python_dir = STAGE_DIR / "python312"
    python_dir.mkdir()
    python_zip = BUILD_DIR / "python-embed.zip"

    print(f"Downloading Python {PYTHON_VERSION} embedded package...")
    try:
        urllib.request.urlretrieve(PYTHON_URL, python_zip)
        print("Extracting Python...")
        with zipfile.ZipFile(python_zip, "r") as zf:
            zf.extractall(python_dir)

        # Add local path to python path (needed for module imports)
        pth_files = list(python_dir.glob("*_pth"))
        if pth_files:
            pth_file = pth_files[0]
            with open(pth_file, "a") as f:
                f.write("\n..\n")  # Add root app dir to sys.path

        print("Python environment setup complete.")
    except Exception as e:
        print(f"Failed to download Python: {e}")
        print("Proceeding without embedded Python. End user will need system Python.")
        shutil.rmtree(python_dir)


def create_readme():
    readme_path = STAGE_DIR / "README_PORTABLE.txt"
    content = f"""STIG Assessor Portable Distribution
Version {VERSION}

This is a fully self-contained distribution of the STIG Assessor.
It requires zero installation, administrator rights, or dependencies.

To run:
1. Double-click launch_gui.bat for the Graphical Interface (Recommended)
2. Double-click launch_web.bat for the local Web Interface

Designed for air-gapped DoD environments.
"""
    readme_path.write_text(content)


def package_zip():
    zip_path = DIST_DIR / f"{APP_NAME}.zip"
    print(f"Creating portable archive at {zip_path}...")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(STAGE_DIR):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(STAGE_DIR.parent)
                zf.write(file_path, arcname)

    print(
        f"Build complete! Portable archive sizes: {zip_path.stat().st_size / (1024*1024):.2f} MB"
    )


def main():
    print(f"=== Building STIG Assessor Portable v{VERSION} ===")
    clean_build()
    copy_source()
    download_python()
    create_readme()
    package_zip()
    print("=== Done ===")


if __name__ == "__main__":
    main()
