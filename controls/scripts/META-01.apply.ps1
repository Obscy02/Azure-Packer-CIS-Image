# Records which baseline version was applied and when, for drift auditing.
param($Context)

$BaselineRegPath = "HKLM:\SOFTWARE\CISBaseline"
Set-RegistryBaseline -Path $BaselineRegPath -Name "Version" -Value $Context.CatalogVersion -Type "String"
Set-RegistryBaseline -Path $BaselineRegPath -Name "BuildDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type "String"
Set-RegistryBaseline -Path $BaselineRegPath -Name "Os" -Value $Context.Os -Type "String"
Set-RegistryBaseline -Path $BaselineRegPath -Name "Level" -Value ([string]$Context.Level) -Type "String"
Set-RegistryBaseline -Path $BaselineRegPath -Name "Role" -Value $Context.Role -Type "String"
