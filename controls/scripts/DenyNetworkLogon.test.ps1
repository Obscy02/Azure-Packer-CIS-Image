# Passes when SeDenyNetworkLogonRight includes every SID in the control's parameters.
param($Context, $Parameters)

$ExportPath = Join-Path $env:TEMP "cis-ura-export.inf"
try {
    Invoke-Native { secedit.exe /export /cfg $ExportPath /areas USER_RIGHTS /quiet } "Secedit User Rights export"
    $Line = Get-Content -Path $ExportPath | Where-Object { $_ -match '^SeDenyNetworkLogonRight\s*=' }
    $Missing = @($Parameters.sids | Where-Object { $Line -notmatch [regex]::Escape($_) })
    $Missing.Count -eq 0
}
finally {
    Remove-Item $ExportPath -Force -ErrorAction SilentlyContinue
}
