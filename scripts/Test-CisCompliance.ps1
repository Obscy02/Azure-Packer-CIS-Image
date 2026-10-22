#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Baseline Compliance Auditor for Windows Server 2022
.DESCRIPTION
    Validates high-impact hardening controls and outputs a clear [PASS]/[FAIL] report.
#>

$FailCount = 0

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
            script:FailCount++
        }
    } catch {
        Write-Host "[ERROR] $Name ($($_))" -ForegroundColor Red
        script:FailCount++
    }
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   CIS Server Hardening Compliance Audit" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Check LSA Protection (RunAsPPL)
Test-Check "LSA Protection (RunAsPPL) Enabled" {
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL -eq 1
}

# 2. Check WDigest Cleartext Caching Disabled
Test-Check "WDigest Cleartext Caching Disabled" {
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential -eq 0
}

# 3. Check SMBv1 Server Disabled
Test-Check "SMBv1 Server Disabled" {
    (Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false
}

# 4. Check LLMNR Disabled
Test-Check "LLMNR Disabled (EnableMulticast = 0)" {
    (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast -eq 0
}

# 5. Check PowerShell Script Block Logging
Test-Check "PowerShell Script Block Logging Enabled" {
    (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1
}

# 6. Check RDP NLA Enforced
Test-Check "RDP Network Level Authentication (NLA) Enforced" {
    (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication -eq 1
}

# 7. Check Schannel TLS 1.2 Enforced for Server
Test-Check "Schannel TLS 1.2 Server Enabled" {
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -eq 1
}

# 8. Check Baseline Version Registry Stamp Exists
Test-Check "Baseline Version Stamp Present" {
    $Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\CISBaseline" -Name "Version" -ErrorAction SilentlyContinue
    $Reg.Version -eq "1.0"
}

Write-Host "=========================================" -ForegroundColor Cyan
if ($FailCount -eq 0) {
    Write-Host " RESULT: ALL CHECKS PASSED SUCCESSFULLY." -ForegroundColor Green
    exit 0
} else {
    Write-Host " RESULT: $FailCount CHECK(S) FAILED." -ForegroundColor Red
    exit 1
}