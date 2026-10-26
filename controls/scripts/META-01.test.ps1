# Passes when the stamped version matches the catalog that was applied.
param($Context)

(Get-ItemProperty -Path "HKLM:\SOFTWARE\CISBaseline" -Name "Version" -ErrorAction Stop).Version -eq $Context.CatalogVersion
