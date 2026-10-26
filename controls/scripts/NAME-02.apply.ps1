# Disables NetBIOS over TCP/IP now, and registers a SYSTEM startup task that
# re-applies it on every boot so NICs added after imaging are covered too.
param($Context)

$NetBiosDir = "$env:ProgramFiles\CIS-Baseline"
New-Item -Path $NetBiosDir -ItemType Directory -Force | Out-Null

$NetBiosScriptContent = @'
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
    ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -ErrorAction SilentlyContinue }
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue |
    Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2} | Out-Null
'@
Set-Content -Path "$NetBiosDir\Disable-NetBIOS.ps1" -Value $NetBiosScriptContent -Force

& "$NetBiosDir\Disable-NetBIOS.ps1"

$TaskAction    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$NetBiosDir\Disable-NetBIOS.ps1`""
$TaskTrigger   = New-ScheduledTaskTrigger -AtStartup
$TaskTrigger.Delay = 'PT1M'
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "CIS-Disable-NetBIOS-OnBoot" -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Force | Out-Null
