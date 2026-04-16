$errs = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('test_fixes\out.ps1', [ref]$tokens, [ref]$errs)
if ($errs) {
    $errs
    exit 1
} else {
    Write-Host 'Syntax OK'
}
