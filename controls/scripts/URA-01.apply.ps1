# Denies network logon to Guests (S-1-5-32-546) and local accounts (S-1-5-114).
param($Context)

$SecEditTemp = Join-Path $env:TEMP "cis-ura.inf"
$SecEditDb   = Join-Path $env:TEMP "cis-ura.sdb"

@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-114
"@ | Set-Content -Path $SecEditTemp -Encoding Unicode -Force

try {
    Invoke-Native { secedit.exe /configure /db $SecEditDb /cfg $SecEditTemp /areas USER_RIGHTS /quiet } "Secedit User Rights Assignment"
}
finally {
    Remove-Item $SecEditTemp, $SecEditDb -Force -ErrorAction SilentlyContinue
}
