# Passes when SeDenyNetworkLogonRight includes both Guests and local accounts.
param($Context)

$ExportPath = Join-Path $env:TEMP "cis-ura-export.inf"
try {
    Invoke-Native { secedit.exe /export /cfg $ExportPath /areas USER_RIGHTS /quiet } "Secedit User Rights export"
    $Line = Get-Content -Path $ExportPath | Where-Object { $_ -match '^SeDenyNetworkLogonRight\s*=' }
    ($Line -match '\*S-1-5-32-546') -and ($Line -match '\*S-1-5-114')
}
finally {
    Remove-Item $ExportPath -Force -ErrorAction SilentlyContinue
}
