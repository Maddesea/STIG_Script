$ErrorActionPreference = 'Continue'
$Log = 'test.log'

try {
    & {
    Set-ItemProperty -Path "HKLM:\Some\Path" -Name "Value" -Value 1
    } *>> $Log
    Write-Host "Success"

    try {
        & {
        Get-ItemProperty -Path "HKLM:\Some\Path"
        } *>> $Log
        Write-Host "Verify Pass"
    } catch {
        Write-Host "Verify Fail"
    }
} catch {
    Write-Host "Failed"
}
