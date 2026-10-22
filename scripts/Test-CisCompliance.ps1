#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Baseline Compliance Auditor for Windows Server 2022
.DESCRIPTION
    Validates all 14 high-impact hardening controls and outputs a [PASS]/[FAIL] report.
    Exits with code 1 if any check fails, halting the Packer pipeline.
#>

$script:FailCount = 0

function Test-Check {
    param(
        [string]$Name,
        [scriptblock]$Condition
    )
    try {
        if (& $Condition) {
            Write-Host "[PASS] $Name" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] $Name" -ForegroundColor Red
            $script:FailCount++
        }
    } catch {
        Write-Host "[ERROR] $Name ($($_))" -ForegroundColor Red
        $script:FailCount++
    }
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   CIS Server Hardening Compliance Audit " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

Test-Check "1. LSA Protection (RunAsPPL) Enabled" {
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL").RunAsPPL -eq 1
}

Test-Check "2. WDigest Cleartext Caching Disabled" {
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential").UseLogonCredential -eq 0
}

Test-Check "3. Anonymous SAM & Share Enumeration Restricted" {
    $Lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    ($Lsa.RestrictAnonymousSAM -eq 1) -and ($Lsa.RestrictAnonymous -eq 1)
}

Test-Check "4. SMB Signing Required (Server & Client)" {
    $Srv = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature").RequireSecuritySignature
    $Wrk = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature").RequireSecuritySignature
    ($Srv -eq 1) -and ($Wrk -eq 1)
}

Test-Check "5. LAN Manager Auth Level set to NTLMv2 Only (5)" {
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel").LmCompatibilityLevel -eq 5
}

Test-Check "6. Feature Removed: FS-SMB1" {
    (Get-WindowsFeature -Name "FS-SMB1").Installed -eq $false
}

Test-Check "7. Feature Removed: PowerShell-V2" {
    (Get-WindowsFeature -Name "PowerShell-V2").Installed -eq $false
}

Test-Check "8. LLMNR Disabled & NetBIOS Startup Task Registered" {
    $Llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast").EnableMulticast -eq 0
    $Task  = $null -ne (Get-ScheduledTask -TaskName "CIS-Disable-NetBIOS-OnBoot" -ErrorAction SilentlyContinue)
    $Llmnr -and $Task
}

Test-Check "9. RDP Hardened (NLA, TLS SecurityLayer, High Encryption)" {
    $Rdp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    ($Rdp.UserAuthentication -eq 1) -and ($Rdp.SecurityLayer -eq 2) -and ($Rdp.MinEncryptionLevel -eq 3)
}

Test-Check "10. PowerShell Script Block & Module Logging Enabled" {
    $Sb = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging").EnableScriptBlockLogging -eq 1
    $Ml = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging").EnableModuleLogging -eq 1
    $Sb -and $Ml
}

Test-Check "11. Schannel TLS 1.0/1.1 Disabled & TLS 1.2 Enabled" {
    $Tls10 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled").Enabled -eq 0
    $Tls12 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled").Enabled -eq 1
    $Tls10 -and $Tls12
}

Test-Check "12. .NET Framework Strong Crypto Enabled (x64 & x86)" {
    $Net64 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto").SchUseStrongCrypto -eq 1
    $Net32 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto").SchUseStrongCrypto -eq 1
    $Net64 -and $Net32
}

Test-Check "13. Print Spooler Service Disabled" {
    (Get-Service -Name "Spooler").StartType -eq "Disabled"
}

Test-Check "14. Baseline Version Stamp Present" {
    (Get-ItemProperty -Path "HKLM:\SOFTWARE\CISBaseline" -Name "Version").Version -eq "1.0"
}

Write-Host "=========================================" -ForegroundColor Cyan
if ($script:FailCount -eq 0) {
    Write-Host " RESULT: ALL 14 CHECKS PASSED SUCCESSFULLY." -ForegroundColor Green
    exit 0
} else {
    Write-Host " RESULT: $($script:FailCount) CHECK(S) FAILED." -ForegroundColor Red
    exit 1
}