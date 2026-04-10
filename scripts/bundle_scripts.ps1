<#
.SYNOPSIS
    Bundles STIG Assessor into a portable script-based package (non-compiled).
.DESCRIPTION
    This script creates a standalone folder containing the source code,
    launchers, and (optionally) vendored dependencies.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$OutDir = Join-Path $ProjectRoot "dist\STIG_Assessor_Scripts"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  STIG Assessor Script Bundler (Portable)   " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Clean previous build
if (Test-Path $OutDir) {
    Write-Host "Cleaning old build at $OutDir..." -ForegroundColor Gray
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Path $OutDir | Out-Null

# 2. Copy Source Code
Write-Host "[1/4] Copying source code..." -ForegroundColor Yellow
$SourceDir = Join-Path $ProjectRoot "stig_assessor"
Copy-Item -Path $SourceDir -Destination $OutDir -Recurse

# 3. Copy Launchers
Write-Host "[2/4] Copying launchers..." -ForegroundColor Yellow
Copy-Item -Path (Join-Path $ProjectRoot "launch.ps1") -Destination $OutDir
Copy-Item -Path (Join-Path $ProjectRoot "launch.sh") -Destination $OutDir

# 4. Vendor Dependencies (Optional/Premium)
Write-Host "[3/4] Vendoring dependencies into 'lib' folder..." -ForegroundColor Yellow
$LibDir = Join-Path $OutDir "lib"
New-Item -ItemType Directory -Path $LibDir | Out-Null

# Using pip to install dependencies locally into lib
# We only install the core requirements (defusedxml and sv-ttk for premium GUI)
# These are optional but make the "portable" version fully featured.
$deps = @("defusedxml", "sv-ttk")
foreach ($dep in $deps) {
    Write-Host "  Installing $dep..." -ForegroundColor DarkGray
    python -m pip install $dep --target $LibDir --no-user --quiet
}

# 5. Finalize
Write-Host "[4/4] Package complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Location: $OutDir" -ForegroundColor Cyan
Write-Host "You can now zip this folder and move it to any air-gapped machine." -ForegroundColor White
Write-Host "Usage on Target:" -ForegroundColor White
Write-Host "  Windows: .\launch.ps1" -ForegroundColor Gray
Write-Host "  Linux:   ./launch.sh" -ForegroundColor Gray
Write-Host ""
