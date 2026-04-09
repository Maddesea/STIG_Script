@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  STIG Assessor — GUI Launcher (Windows 11)
REM  Double-click to launch the graphical interface.
REM ═══════════════════════════════════════════════════════════════════
title STIG Assessor - GUI
cd /d "%~dp0"

REM Check for portable Python first, then system Python
if exist "%~dp0python\python.exe" (
    set PYTHON="%~dp0python\python.exe"
) else if exist "%~dp0python312\python.exe" (
    set PYTHON="%~dp0python312\python.exe"
) else (
    where python >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python not found. Place Python in a "python" subfolder or install it system-wide.
        pause
        exit /b 1
    )
    set PYTHON=python
)

echo Starting STIG Assessor GUI...
%PYTHON% -m stig_assessor.ui.cli --gui
if errorlevel 1 (
    echo.
    echo ERROR: Failed to launch the GUI. Please check errors above.
)
pause
