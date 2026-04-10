# STIG Assessor Automated Release Packager
# Generates Full (Bundled Python 3.12), Lean (Source + Wheels), and Standalone EXE bundles.

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$DistRootDir = Join-Path $ProjectRoot "dist"
$PythonVersion = "3.12.2"
$PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   STIG Assessor Release Packager (Air-Gap)  " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Preparation
# 2. Build Standalone EXE
Write-Host "`n[1/4] Building Standalone EXE..." -ForegroundColor Yellow
& "$ProjectRoot\build_portable.ps1"

# 3. Preparation for Portables
$TempDir = Join-Path $DistRootDir "temp_build"
if (Test-Path $TempDir) { Remove-Item -Recurse -Force $TempDir }
New-Item -ItemType Directory -Path $TempDir | Out-Null

# 3. Create Lean Portable (Source + Wheels)
Write-Host "`n[2/4] Creating Lean Portable Bundle..." -ForegroundColor Yellow
$LeanDir = Join-Path $DistRootDir "STIG_Assessor_Lean_Portable"
New-Item -ItemType Directory -Path $LeanDir | Out-Null

Copy-Item -Path (Join-Path $ProjectRoot "stig_assessor") -Destination $LeanDir -Recurse
Copy-Item -Path (Join-Path $ProjectRoot "launch.ps1") -Destination $LeanDir
Copy-Item -Path (Join-Path $ProjectRoot "launch.sh") -Destination $LeanDir
Copy-Item -Path (Join-Path $ProjectRoot "README.md") -Destination $LeanDir
Copy-Item -Path (Join-Path $ProjectRoot "USER_MANUAL.md") -Destination $LeanDir

$LeanWheels = Join-Path $LeanDir "wheels"
New-Item -ItemType Directory -Path $LeanWheels | Out-Null
Write-Host "  Downloading offline wheels for win_amd64..." -ForegroundColor Gray
& python -m pip download --only-binary=:all: --platform win_amd64 --python-version 3.12 -d $LeanWheels defusedxml sv-ttk

# 4. Create Full Portable (Source + Included Python 3.12)
Write-Host "`n[3/4] Creating Full Portable Bundle (w/ Python 3.12)..." -ForegroundColor Yellow
$FullDir = Join-Path $DistRootDir "STIG_Assessor_Full_Portable"
New-Item -ItemType Directory -Path $FullDir | Out-Null

Copy-Item -Path (Join-Path $ProjectRoot "stig_assessor") -Destination $FullDir -Recurse
Copy-Item -Path (Join-Path $ProjectRoot "launch.ps1") -Destination $FullDir
Copy-Item -Path (Join-Path $ProjectRoot "launch.sh") -Destination $FullDir
Copy-Item -Path (Join-Path $ProjectRoot "README.md") -Destination $FullDir

$PyDir = Join-Path $FullDir "python312"
New-Item -ItemType Directory -Path $PyDir | Out-Null

$PyZip = Join-Path $TempDir "python_embedded.zip"
Write-Host "  Downloading Python $PythonVersion embedded..." -ForegroundColor Gray
Invoke-WebRequest -Uri $PythonUrl -OutFile $PyZip
Expand-Archive -Path $PyZip -DestinationPath $PyDir

# Enable site-packages and root in embedded python
$pthFile = Join-Path $PyDir "python312._pth"
if (Test-Path $pthFile) {
    # Ensure it can see the source in '..' and the local folder '.'
    "python312.zip`n.`n..`n`nimport site" | Set-Content $pthFile
}

# Install pip and dependencies into the embedded python
Write-Host "  Installing pip and dependencies into Bundled Python..." -ForegroundColor Gray
$PyExe = Join-Path $PyDir "python.exe"
$GetPip = Join-Path $TempDir "get-pip.py"
Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $GetPip
& "$PyExe" "$GetPip" --no-warn-script-location --quiet

& "$PyExe" -m pip install --no-warn-script-location --quiet defusedxml sv-ttk

# 5. Finalize
Write-Host "`n[4/4] Finalizing Releases..." -ForegroundColor Yellow
Remove-Item -Recurse -Force $TempDir

Write-Host "`nRelease Generation Complete!" -ForegroundColor Green
Write-Host "---------------------------------------------"
Write-Host "1. EXE:  $DistRootDir\STIG_Assessor.exe"
Write-Host "2. Lean: $DistRootDir\STIG_Assessor_Lean_Portable"
Write-Host "3. Full: $DistRootDir\STIG_Assessor_Full_Portable"
Write-Host "---------------------------------------------"
