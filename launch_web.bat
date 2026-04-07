@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  STIG Assessor — Web Interface Launcher (Windows 11)
REM  Double-click to start the local web server, then open the browser.
REM ═══════════════════════════════════════════════════════════════════
title STIG Assessor - Web Interface
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

echo Starting STIG Assessor Web Server on http://127.0.0.1:8080 ...
echo Press Ctrl+C to stop the server.
echo.
%PYTHON% -m stig_assessor.ui.cli --web
if errorlevel 1 (
    echo.
    echo If the above failed, try:  %PYTHON% STIG_Script.py --web
    %PYTHON% STIG_Script.py --web
)
pause
