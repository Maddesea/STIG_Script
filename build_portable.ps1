<#
.SYNOPSIS
    Builds a standalone, air-gap compatible portable executable for STIG Assessor.

.DESCRIPTION
    This script compiles the entire Python project (including the web assets
    and standard libraries) into a single standalone Windows executable (.exe).
    It requires PyInstaller to be installed. If PyInstaller is missing, the
    script will attempt to install it automatically.

.NOTES
    Output is placed in: .\dist\STIG_Assessor.exe
#>

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  STIG Assessor Portable Executable Builder  " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify Python is installed and accessible
Write-Host "[1/5] Verifying Python environment..." -ForegroundColor Yellow
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in the PATH. Please install Python 3.9+ to run this builder."
    exit 1
}

# 2. Ensure PyInstaller is installed
Write-Host "[2/5] Checking for PyInstaller..." -ForegroundColor Yellow
if (-not (Get-Command "pyinstaller" -ErrorAction SilentlyContinue)) {
    Write-Host "PyInstaller not found. Attempting to install via pip from local wheels..." -ForegroundColor DarkGray
    python -m pip install --no-index --find-links=wheels pyinstaller
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install PyInstaller from local wheels. Ensure /wheels folder contains the required PyInstaller packages."
        exit 1
    }
}

# 3. Clean previous builds
Write-Host "[3/5] Cleaning previous build artifacts..." -ForegroundColor Yellow
if (Test-Path ".\build") { Remove-Item -Recurse -Force ".\build" }
if (Test-Path ".\dist") { Remove-Item -Recurse -Force ".\dist" }
if (Test-Path ".\STIG_Assessor.spec") { Remove-Item -Force ".\STIG_Assessor.spec" }

# 4. Compile the application
Write-Host "[4/5] Compiling STIG Assessor to standalone .exe..." -ForegroundColor Yellow
Write-Host "This will take a few minutes as it bundles all dependencies..." -ForegroundColor DarkGray

$webAssets = "stig_assessor/ui/web/assets;stig_assessor/ui/web/assets"
$entryPoint = "stig_assessor/ui/cli.py"

# PyInstaller arguments:
# --onefile     : Package everything into a single .exe
# --name        : Name of the resulting executable
# --clean       : Clean PyInstaller cache
# --add-data    : Include web UI assets 
# --hidden-import: Ensure tkinter and sqlite3 are explicitly bundled

$pyinstallerArgs = @(
    "--onefile",
    "--name", "STIG_Assessor",
    "--clean",
    "--add-data", $webAssets,
    "--hidden-import", "tkinter",
    "--hidden-import", "sqlite3",
    $entryPoint
)

# Run PyInstaller
& pyinstaller $pyinstallerArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation failed. Check the error output above."
    exit $LASTEXITCODE
}

# 5. Finish
Write-Host "[5/5] Build Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Your portable executable has been created at: .\dist\STIG_Assessor.exe" -ForegroundColor Cyan
Write-Host "You can now distribute this single file to any air-gapped Windows machine." -ForegroundColor Cyan
Write-Host "No Python installation is required on the target machine." -ForegroundColor Cyan
Write-Host ""
