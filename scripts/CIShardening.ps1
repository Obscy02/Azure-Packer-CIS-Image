#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Production Windows Server 2022 Member Server Hardening Script (VMware / Hyper-V / Packer)
.DESCRIPTION
    Applies CIS Level 1 baseline controls safely:
    - Restricted to Standalone (2) or Member Servers (3).
    - Uses try/finally to guarantee transcript closure even on fatal throws.
    - Localizes $ErrorActionPreference in Invoke-Native to prevent harmless stderr warnings from killing the build.
    - Captures native command output into exceptions for easy 2 AM debugging.
    - Persists NetBIOS disablement via an admin-only script & delayed SYSTEM startup task.
    - Stamps a version registry key at completion for Cyber Essentials and drift auditing.
#>

[CmdletBinding()]
param(
    [switch]$ApplyUserRights
)

$ErrorActionPreference = "Stop"

# Setup Transcript Logging inside try/finally block so it never stays open/half-flushed on failure
$LogPath = "$env:SystemRoot\Temp\cis-hardening.log"
Start-Transcript -Path $LogPath -Force | Out-Null

try {
    Write-Host "[*] Starting Windows Server 2022 Hardening Baseline..." -ForegroundColor Cyan

    # 0. Role Guard: Allow only Standalone Server (2) or Member Server (3). Abort on Workstations (0/1) or DCs (4/5).
    $DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if ($DomainRole -notin @(2, 3)) {
        Throw "ABORTING: Server role $DomainRole is not a Standalone Server (2) or Member Server (3). Script halted."
    }

    # Helper Function for Registry Keys
    function Set-RegistryBaseline {
        param (
            [Parameter(Mandatory=$true)][string]$Path,
            [Parameter(Mandatory=$true)][string]$Name,
            [Parameter(Mandatory=$true)]$Value,
            [ValidateSet("DWord", "String", "MultiString", "QWord")]
            [string]$Type = "DWord"
        )
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }

    # Helper Function for Native Commands (wevtutil, auditpol, secedit) with robust stderr handling
    function Invoke-Native {
        param([scriptblock]$Command, [string]$Description)
        $ErrorActionPreference = 'Continue' # Local override so stderr warnings don't trigger global Stop
        $Output = & $Command 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "$Description failed with exit code $LASTEXITCODE. Output: $($Output -join ' ')"
        }
    }

    # ==============================================================================
    # 1. CREDENTIAL PROTECTION & ANONYMOUS ENUMERATION (LSASS, WDigest, SAM)
    # ==============================================================================
    Write-Host "[1/9] Configuring Credential Protection (RunAsPPL, WDigest, Anonymous SAM)..."
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -Value 0
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3

    # ==============================================================================
    # 2. SMB SIGNING & NTLMv2 AUTHENTICATION
    # ==============================================================================
    Write-Host "[2/9] Enforcing SMB Signing and NTLMv2..."
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

    # ==============================================================================
    # 3. REMOVE SMBv1 & POWERSHELL v2 DOWNGRADE ENGINE (Server 2022 Native Features)
    # ==============================================================================
    Write-Host "[3/9] Removing deprecated features (FS-SMB1, PowerShell-V2)..."
    foreach ($Feature in 'FS-SMB1', 'PowerShell-V2') {
        $FeatureStatus = Get-WindowsFeature -Name $Feature -ErrorAction SilentlyContinue
        if ($FeatureStatus -and $FeatureStatus.Installed) {
            Uninstall-WindowsFeature -Name $Feature -Confirm:$false | Out-Null
            Write-Host " -> Uninstalled feature: $Feature" -ForegroundColor DarkGray
        }
    }

    # ==============================================================================
    # 4. DISABLE LLMNR & PERSIST NETBIOS DISABLEMENT VIA ADMIN-ONLY SCRIPT & TASK
    # ==============================================================================
    Write-Host "[4/9] Disabling LLMNR and setting up NetBIOS remediation task for new NICs..."
    Set-RegistryBaseline -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

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

    $TaskAction   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$NetBiosDir\Disable-NetBIOS.ps1`""
    $TaskTrigger  = New-ScheduledTaskTrigger -AtStartup
    $TaskTrigger.Delay = 'PT1M'
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "CIS-Disable-NetBIOS-OnBoot" -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Force | Out-Null

    # ==============================================================================
    # 5. RDP HARDENING (CIS POLICY PATHS)
    # ==============================================================================
    Write-Host "[5/9] Hardening Remote Desktop Services..."
    $RdpPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-RegistryBaseline -Path $RdpPolicyPath -Name "UserAuthentication" -Value 1
    Set-RegistryBaseline -Path $RdpPolicyPath -Name "SecurityLayer" -Value 2
    Set-RegistryBaseline -Path $RdpPolicyPath -Name "MinEncryptionLevel" -Value 3
    Set-RegistryBaseline -Path $RdpPolicyPath -Name "fDisableCdm" -Value 1

    # ==============================================================================
    # 6. POWERSHELL LOGGING & OPERATIONAL LOG EXPANSION
    # ==============================================================================
    Write-Host "[6/9] Enabling PowerShell Logging & Expanding Operational Log..."
    Set-RegistryBaseline -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type "String"

    Invoke-Native { wevtutil.exe sl Microsoft-Windows-PowerShell/Operational /ms:268435456 } "PowerShell Operational log expansion"

    # ==============================================================================
    # 7. SCHANNEL TLS 1.2+ & .NET FRAMEWORK STRONG CRYPTO
    # ==============================================================================
    Write-Host "[7/9] Enforcing Schannel TLS 1.2+ and .NET Strong Crypto..."
    $InsecureProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    foreach ($Proto in $InsecureProtocols) {
        foreach ($Role in @("Client", "Server")) {
            $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Proto\$Role"
            Set-RegistryBaseline -Path $RegPath -Name "Enabled" -Value 0
            Set-RegistryBaseline -Path $RegPath -Name "DisabledByDefault" -Value 1
        }
    }

    foreach ($Role in @("Client", "Server")) {
        $Tls12Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$Role"
        Set-RegistryBaseline -Path $Tls12Path -Name "Enabled" -Value 1
        Set-RegistryBaseline -Path $Tls12Path -Name "DisabledByDefault" -Value 0
    }

    $DotNetPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
    )
    foreach ($NetPath in $DotNetPaths) {
        Set-RegistryBaseline -Path $NetPath -Name "SchUseStrongCrypto" -Value 1
        Set-RegistryBaseline -Path $NetPath -Name "SystemDefaultTlsVersions" -Value 1
    }

    # ==============================================================================
    # 8. USER RIGHTS ASSIGNMENT (Gated behind -ApplyUserRights switch for standalone templates)
    # ==============================================================================
    if ($ApplyUserRights) {
        Write-Host "[8/9] Applying User Rights Assignments (Deny Network Logon)..."
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

        Invoke-Native { secedit.exe /configure /db $SecEditDb /cfg $SecEditTemp /areas USER_RIGHTS /quiet } "Secedit User Rights Assignment"
        Remove-Item $SecEditTemp, $SecEditDb -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "[8/9] Skipping User Rights Assignment (Handled via Active Directory GPO in production)." -ForegroundColor Yellow
    }

    # ==============================================================================
    # 9. ADVANCED AUDIT POLICY, 1GB SECURITY LOG, FIREWALL & BASELINE VERSION STAMP
    # ==============================================================================
    Write-Host "[9/9] Configuring Audit Subcategories, 1GB Security Log, Print Spooler, and Version Stamp..."
    Set-RegistryBaseline -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1
    Set-RegistryBaseline -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

    Invoke-Native { wevtutil.exe sl Security /ms:1073741824 } "Security log resize"

    # Complete CIS Audit Subcategory Matrix
    $AuditSettings = @(
        @{ Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # Credential Validation
        @{ Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # Logon
        @{ Guid = "{0CCE921B-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $false }, # Special Logon
        @{ Guid = "{0CCE9217-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $false; IncludeFailure = $true  }, # Account Lockout
        @{ Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # User Account Management
        @{ Guid = "{0CCE9237-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # Security Group Management
        @{ Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $false }, # Process Creation (Command Line)
        @{ Guid = "{0CCE9211-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # Security System Extension
        @{ Guid = "{0CCE9227-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # Other Object Access Events
        @{ Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $true;  IncludeFailure = $true  }, # Audit Policy Change
        @{ Guid = "{0CCE9228-69AE-11D9-BED3-505054503030}"; IncludeSuccess = $false; IncludeFailure = $true  }  # Sensitive Privilege Use (Failure only)
    )

    foreach ($Setting in $AuditSettings) {
        $Suc = if ($Setting.IncludeSuccess) { "enable" } else { "disable" }
        $Fai = if ($Setting.IncludeFailure) { "enable" } else { "disable" }
        Invoke-Native { auditpol.exe /set /subcategory:"$($Setting.Guid)" /success:$Suc /failure:$Fai } "Auditpol setting $($Setting.Guid)"
    }

    # Disable Print Spooler on Member Servers
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue

    # NOTE ON WINDOWS FIREWALL:
    # Windows Firewall profiles (Domain, Private, Public) and inbound block rules are intentionally 
    # left under the management of the EDR platform and Active Directory Group Policy post-deployment.

    # Stamp Baseline Version Registry Key for Cyber Essentials and Drift Auditing
    $BaselineRegPath = "HKLM:\SOFTWARE\CISBaseline"
    Set-RegistryBaseline -Path $BaselineRegPath -Name "Version" -Value "1.0" -Type "String"
    Set-RegistryBaseline -Path $BaselineRegPath -Name "BuildDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type "String"

    Write-Host "[+] Baseline Hardening Complete. REBOOT REQUIRED for RunAsPPL, Schannel, and feature removals." -ForegroundColor Green
}
finally {
    Stop-Transcript | Out-Null
}