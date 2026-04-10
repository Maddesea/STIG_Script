#Requires -Version 5.1
<#
.SYNOPSIS
    STIG Assessor Launcher (PowerShell)
.DESCRIPTION
    Launch the STIG Assessor in GUI, Web, or CLI mode.
    Auto-detects portable or system Python installation.
.PARAMETER Mode
    Interface mode: 'gui' (default), 'web', or 'cli'
.EXAMPLE
    .\launch.ps1
    .\launch.ps1 -Mode web
    .\launch.ps1 -Mode cli -Arguments "create --help"
#>
param(
    [ValidateSet('gui', 'web', 'cli')]
    [string]$Mode = 'gui',

    [string]$Arguments = ''
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Discover Python
$IsWin = $IsWin -or ($env:OS -eq "Windows_NT")
$libDir = Join-Path $ScriptDir "lib"
$venvDir = Join-Path $ScriptDir "venv"
$wheelsDir = Join-Path $ScriptDir "wheels"

# 1. Prioritize local venv if it exists
if (Test-Path $venvDir) {
    if ($IsWin) {
        $Python = Join-Path $venvDir "Scripts\python.exe"
    } else {
        $Python = Join-Path $venvDir "bin/python3"
    }
    if (Test-Path $Python) {
        Write-Host "Local venv detected and active." -ForegroundColor Gray
    } else {
        $Python = $null
    }
}

# 2. Configure PYTHONPATH for vendored dependencies if present
if (Test-Path $libDir) {
    if ($IsWin) {
        $env:PYTHONPATH = "$libDir;$env:PYTHONPATH"
    } else {
        $env:PYTHONPATH = "${libDir}:$env:PYTHONPATH"
    }
    Write-Host "Local 'lib' detected, added to PYTHONPATH." -ForegroundColor Gray
}

$PythonCandidates = @()
if ($IsWin) {
    $PythonCandidates += (Join-Path $ScriptDir 'python\python.exe')
    $PythonCandidates += (Join-Path $ScriptDir 'python312\python.exe')
}

if (-not $Python) {
    foreach ($candidate in $PythonCandidates) {
        if (Test-Path $candidate) {
            $Python = $candidate
            break
        }
    }
}

if (-not $Python) {
    # Check system path
    $cmds = @("python", "python3")
    foreach ($c in $cmds) {
        $found = (Get-Command $c -ErrorAction SilentlyContinue)
        if ($found) {
            $systemPython = $found.Source
            
            # If we have a system python but no local venv/lib, offer to create one from wheels
            if (-not (Test-Path $libDir) -and (Test-Path $wheelsDir)) {
                Write-Host "Dependencies not found, but bundled wheels detected." -ForegroundColor Yellow
                $confirm = Read-Host "Create a local virtual environment (venv) using system Python? [Y/n]"
                if ($confirm -ne "n") {
                    Write-Host "Creating venv..." -ForegroundColor Cyan
                    & "$systemPython" -m venv "$venvDir"
                    $Python = if ($IsWin) { Join-Path $venvDir "Scripts\python.exe" } else { Join-Path $venvDir "bin/python3" }
                    Write-Host "Installing dependencies from wheels..." -ForegroundColor Cyan
                    & "$Python" -m pip install --no-index --find-links="$wheelsDir" defusedxml sv-ttk
                    Write-Host "Setup complete." -ForegroundColor Green
                } else {
                    $Python = $systemPython
                }
            } else {
                $Python = $systemPython
            }
            break
        }
    }

    if (-not $Python) {
        Write-Error "Python not found. Please install Python or use the full bundled version."
        exit 1
    }
}

Write-Host "Using Python: $Python" -ForegroundColor Cyan

switch ($Mode) {
    'gui' {
        Write-Host "Starting STIG Assessor GUI..." -ForegroundColor Green
        & "$Python" -m stig_assessor.ui.cli --gui
    }
    'web' {
        Write-Host "Starting STIG Assessor Web Server on http://127.0.0.1:8080 ..." -ForegroundColor Green
        Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
        & "$Python" -m stig_assessor.ui.cli --web
    }
    'cli' {
        if ($Arguments) {
            & "$Python" -m stig_assessor.ui.cli $Arguments.Split(' ')
        } else {
            & "$Python" -m stig_assessor.ui.cli --help
        }
    }
}
