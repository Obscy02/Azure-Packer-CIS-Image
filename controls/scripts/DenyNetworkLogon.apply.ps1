# Sets "Deny access to this computer from the network" to the SIDs in the control's parameters.
# Used by URA-01 (member servers: Guests + local accounts) and URA-02 (DCs: Guests only).
param($Context, $Parameters)

$SecEditTemp = Join-Path $env:TEMP "cis-ura.inf"
$SecEditDb   = Join-Path $env:TEMP "cis-ura.sdb"

@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeDenyNetworkLogonRight = $($Parameters.sids -join ',')
"@ | Set-Content -Path $SecEditTemp -Encoding Unicode -Force

try {
    Invoke-Native { secedit.exe /configure /db $SecEditDb /cfg $SecEditTemp /areas USER_RIGHTS /quiet } "Secedit User Rights Assignment"
}
finally {
    Remove-Item $SecEditTemp, $SecEditDb -Force -ErrorAction SilentlyContinue
}
