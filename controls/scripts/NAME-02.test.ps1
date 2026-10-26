# Passes when the NetBIOS startup task is registered.
param($Context)

$null -ne (Get-ScheduledTask -TaskName "CIS-Disable-NetBIOS-OnBoot" -ErrorAction SilentlyContinue)
