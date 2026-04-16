$ErrorActionPreference = 'Continue'
$DryRun = $false
$Log = "stig_fix_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Results = @()

Write-Host "[1/1] V-12346 - Test Rule Title Windows" -ForegroundColor Cyan
$EvidLog = "evidence\V-12346_out.log"
"--- PRE-FIX CHECK ---" | Out-File $EvidLog -Encoding utf8
try {
    & {
    powershell
    } *>> $EvidLog
} catch {
}
