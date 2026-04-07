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
$PythonCandidates = @(
    (Join-Path $ScriptDir 'python\python.exe'),
    (Join-Path $ScriptDir 'python312\python.exe'),
    (Join-Path $ScriptDir 'python311\python.exe')
)

$Python = $null
foreach ($candidate in $PythonCandidates) {
    if (Test-Path $candidate) {
        $Python = $candidate
        break
    }
}

if (-not $Python) {
    $Python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $Python) {
        Write-Error "Python not found. Place Python in a 'python' subfolder or install system-wide."
        exit 1
    }
}

Write-Host "Using Python: $Python" -ForegroundColor Cyan

switch ($Mode) {
    'gui' {
        Write-Host "Starting STIG Assessor GUI..." -ForegroundColor Green
        & $Python -m stig_assessor.ui.cli --gui
    }
    'web' {
        Write-Host "Starting STIG Assessor Web Server on http://127.0.0.1:8080 ..." -ForegroundColor Green
        Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
        & $Python -m stig_assessor.ui.cli --web
    }
    'cli' {
        if ($Arguments) {
            & $Python -m stig_assessor.ui.cli $Arguments.Split(' ')
        } else {
            & $Python -m stig_assessor.ui.cli --help
        }
    }
}
