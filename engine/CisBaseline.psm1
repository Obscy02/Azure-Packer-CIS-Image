#Requires -Version 5.1
<#
.SYNOPSIS
    CIS baseline engine: loads the controls catalog, filters it, and applies or tests each control.
.DESCRIPTION
    Every control in controls/catalog.json has a "type". Each type has one Apply handler
    (Invoke-CisControl) and one Test handler (Test-CisControl), so the hardening and the
    compliance check always read the same data and can't drift apart.
    Must stay compatible with Windows PowerShell 5.1, the default on the build VM.
#>

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
    param(
        [scriptblock]$Command,
        [string]$Description,
        [switch]$PassThru
    )
    $ErrorActionPreference = 'Continue' # Local override so stderr warnings don't trigger global Stop
    $Output = & $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE. Output: $($Output -join ' ')"
    }
    if ($PassThru) { $Output }
}

# Role Guard: Allow only Standalone Server (2) or Member Server (3). Abort on Workstations (0/1) or DCs (4/5).
function Assert-CisSupportedRole {
    $DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if ($DomainRole -notin @(2, 3)) {
        throw "ABORTING: Server role $DomainRole is not a Standalone Server (2) or Member Server (3)."
    }
}

function Get-CisCatalog {
    param([Parameter(Mandatory=$true)][string]$Path)

    $FullPath = (Resolve-Path -Path $Path).Path
    $Catalog  = Get-Content -Path $FullPath -Raw -Encoding UTF8 | ConvertFrom-Json
    # Script controls reference their .ps1 files relative to the catalog's folder
    $Catalog | Add-Member -NotePropertyName Root -NotePropertyValue (Split-Path -Parent $FullPath) -Force
    $Catalog
}

function Select-CisControl {
    param(
        [Parameter(Mandatory=$true)]$Catalog,
        [Parameter(Mandatory=$true)][string]$Os,
        [ValidateSet(1, 2)][int]$Level = 1,
        [string]$Platform,
        [string[]]$Include = @(),
        [string[]]$Exclude = @()
    )

    $KnownIds = @($Catalog.controls | ForEach-Object { $_.id })
    $Unknown  = @($Include + $Exclude | Where-Object { $_ -and ($_ -notin $KnownIds) })
    if ($Unknown.Count -gt 0) {
        throw "Unknown control id(s): $($Unknown -join ', ')"
    }

    # Level 2 includes everything in Level 1. Opt-in controls only run when explicitly included.
    @($Catalog.controls | Where-Object {
        ($_.os -contains $Os) -and
        ($_.cis.level -le $Level) -and
        ((-not $Platform) -or ($_.platforms -contains $Platform)) -and
        ($_.id -notin $Exclude) -and
        ($_.enabledByDefault -or ($_.id -in $Include))
    })
}

function Get-RegistryKind {
    param($Setting)
    if ($Setting.kind) { $Setting.kind } else { "DWord" }
}

function Get-ControlScriptPath {
    param($Control, $Context, [string]$Stage)
    Join-Path -Path $Context.ControlsRoot -ChildPath $Control.$Stage
}

function Invoke-CisControl {
    param(
        [Parameter(Mandatory=$true)]$Control,
        [Parameter(Mandatory=$true)]$Context
    )

    switch ($Control.type) {
        'registry' {
            foreach ($Setting in $Control.settings) {
                Set-RegistryBaseline -Path $Setting.path -Name $Setting.name -Value $Setting.value -Type (Get-RegistryKind $Setting)
            }
        }
        'feature' {
            $FeatureStatus = Get-WindowsFeature -Name $Control.feature -ErrorAction SilentlyContinue
            if ($FeatureStatus -and $FeatureStatus.Installed) {
                Uninstall-WindowsFeature -Name $Control.feature -Confirm:$false | Out-Null
                Write-Host " -> Uninstalled feature: $($Control.feature)" -ForegroundColor DarkGray
            }
        }
        'service' {
            if (-not (Get-Service -Name $Control.service -ErrorAction SilentlyContinue)) {
                Write-Host " -> Service $($Control.service) not present, nothing to do" -ForegroundColor DarkGray
                return
            }
            if ($Control.startupType -eq 'Disabled') {
                Stop-Service -Name $Control.service -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $Control.service -StartupType $Control.startupType
        }
        'auditpol' {
            foreach ($Sub in $Control.subcategories) {
                $Suc = if ($Sub.success) { "enable" } else { "disable" }
                $Fai = if ($Sub.failure) { "enable" } else { "disable" }
                Invoke-Native { auditpol.exe /set /subcategory:"$($Sub.guid)" /success:$Suc /failure:$Fai } "Auditpol setting $($Sub.name)"
            }
        }
        'eventlog' {
            Invoke-Native { wevtutil.exe sl "$($Control.log)" "/ms:$($Control.maxSizeBytes)" } "Resize of $($Control.log) log"
        }
        'script' {
            & (Get-ControlScriptPath $Control $Context 'apply') -Context $Context | Out-Null
        }
        default {
            throw "Control $($Control.id) has unknown type '$($Control.type)'"
        }
    }
}

function Get-AuditInclusionSetting {
    param($Subcategory)
    if ($Subcategory.success -and $Subcategory.failure) { return "Success and Failure" }
    if ($Subcategory.success) { return "Success" }
    if ($Subcategory.failure) { return "Failure" }
    "No Auditing"
}

function Test-CisControl {
    param(
        [Parameter(Mandatory=$true)]$Control,
        [Parameter(Mandatory=$true)]$Context
    )

    $Problems = @()
    try {
        switch ($Control.type) {
            'registry' {
                foreach ($Setting in $Control.settings) {
                    $Actual = $null
                    try {
                        $Actual = (Get-ItemProperty -Path $Setting.path -Name $Setting.name -ErrorAction Stop).($Setting.name)
                    } catch {
                        $Actual = '<missing>'
                    }
                    # Compare as strings so JSON integer types don't matter (Int32 vs Int64)
                    if ("$Actual" -ne "$($Setting.value)") {
                        $Problems += "$($Setting.path)\$($Setting.name) = $Actual (expected $($Setting.value))"
                    }
                }
            }
            'feature' {
                $FeatureStatus = Get-WindowsFeature -Name $Control.feature -ErrorAction SilentlyContinue
                if ($FeatureStatus -and $FeatureStatus.Installed) {
                    $Problems += "Feature $($Control.feature) is still installed"
                }
            }
            'service' {
                $Svc = Get-Service -Name $Control.service -ErrorAction SilentlyContinue
                if ($Svc) {
                    if ("$($Svc.StartType)" -ne $Control.startupType) {
                        $Problems += "Service $($Control.service) start type is $($Svc.StartType) (expected $($Control.startupType))"
                    }
                } elseif ($Control.startupType -ne 'Disabled') {
                    $Problems += "Service $($Control.service) is not present"
                }
            }
            'auditpol' {
                foreach ($Sub in $Control.subcategories) {
                    $Lines = Invoke-Native { auditpol.exe /get /subcategory:"$($Sub.guid)" /r } "Auditpol query $($Sub.name)" -PassThru
                    $Row = @($Lines | ForEach-Object { "$_" } | Where-Object { $_.Trim() } | ConvertFrom-Csv) | Select-Object -First 1
                    $Expected = Get-AuditInclusionSetting $Sub
                    if ($Row.'Inclusion Setting' -ne $Expected) {
                        $Problems += "$($Sub.name) is '$($Row.'Inclusion Setting')' (expected '$Expected')"
                    }
                }
            }
            'eventlog' {
                $Log = Get-WinEvent -ListLog $Control.log -ErrorAction Stop
                if ($Log.MaximumSizeInBytes -lt $Control.maxSizeBytes) {
                    $Problems += "$($Control.log) max size is $($Log.MaximumSizeInBytes) bytes (expected at least $($Control.maxSizeBytes))"
                }
            }
            'script' {
                $Result = & (Get-ControlScriptPath $Control $Context 'test') -Context $Context | Select-Object -Last 1
                if (-not $Result) {
                    $Problems += "Test script returned false"
                }
            }
            default {
                $Problems += "Unknown control type '$($Control.type)'"
            }
        }
    } catch {
        $Problems += "Error: $_"
    }

    [pscustomobject]@{
        Id     = $Control.id
        Title  = $Control.title
        Passed = ($Problems.Count -eq 0)
        Detail = ($Problems -join '; ')
    }
}

# Runs the selected controls in catalog order. Returns the number of failures
# (always 0 in Apply mode, where any error throws instead).
function Invoke-CisBaselineRun {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Apply', 'Test')][string]$Mode,
        [Parameter(Mandatory=$true)][object[]]$Controls,
        [Parameter(Mandatory=$true)]$Context
    )

    $Total = $Controls.Count
    $FailCount = 0
    for ($i = 0; $i -lt $Total; $i++) {
        $Control = $Controls[$i]
        if ($Mode -eq 'Apply') {
            Write-Host "[$($i + 1)/$Total] $($Control.id) $($Control.title)"
            # Discard any stray output so the function only returns the fail count
            Invoke-CisControl -Control $Control -Context $Context | Out-Null
        } else {
            $Result = Test-CisControl -Control $Control -Context $Context
            if ($Result.Passed) {
                Write-Host "[PASS] $($Control.id) $($Control.title)" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] $($Control.id) $($Control.title): $($Result.Detail)" -ForegroundColor Red
                $FailCount++
            }
        }
    }
    $FailCount
}

Export-ModuleMember -Function Set-RegistryBaseline, Invoke-Native, Assert-CisSupportedRole, Get-CisCatalog,
    Select-CisControl, Invoke-CisControl, Test-CisControl, Invoke-CisBaselineRun
