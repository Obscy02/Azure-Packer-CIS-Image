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

# Role Guard: the chosen profile must match the machine. Member server profile (ms) needs a
# Standalone (2) or Member Server (3); domain controller profile (dc) needs a DC (4/5). Workstations (0/1) are refused.
function Get-CisDomainRole {
    (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
}

function Assert-CisSupportedRole {
    param([ValidateSet('ms', 'dc')][string]$Role = 'ms')

    $DomainRole = Get-CisDomainRole
    $Allowed = @{ ms = @(2, 3); dc = @(4, 5) }
    if ($DomainRole -in $Allowed[$Role]) { return }

    $Hint = switch ($DomainRole) {
        { $_ -in 4, 5 } { "This machine is a domain controller; use -Role dc." }
        { $_ -in 2, 3 } { "This machine is not a domain controller; use -Role ms." }
        default         { "This machine is a workstation, which this baseline doesn't support." }
    }
    throw "ABORTING: profile '$Role' doesn't match this machine (DomainRole $DomainRole). $Hint"
}

function Get-CisCatalog {
    param([Parameter(Mandatory=$true)][string]$Path)

    $FullPath = (Resolve-Path -Path $Path).Path
    $Catalog  = Get-Content -Path $FullPath -Raw -Encoding UTF8 | ConvertFrom-Json
    # Script controls reference their .ps1 files relative to the catalog's folder
    $Catalog | Add-Member -NotePropertyName Root -NotePropertyValue (Split-Path -Parent $FullPath) -Force
    $Catalog
}

# CIS recommendation numbers for a control on one OS. Empty means it's extra hardening there.
function Get-CisRef {
    param([Parameter(Mandatory=$true)]$Control, [Parameter(Mandatory=$true)][string]$Os)
    if ($Control.cis -and $Control.cis.$Os) { @($Control.cis.$Os) } else { @() }
}

function Select-CisControl {
    param(
        [Parameter(Mandatory=$true)]$Catalog,
        [Parameter(Mandatory=$true)][string]$Os,
        [ValidateSet(1, 2)][int]$Level = 1,
        [ValidateSet('ms', 'dc')][string]$Role = 'ms',
        [string]$Platform,
        [string[]]$Include = @(),
        [string[]]$Exclude = @(),
        # Drop controls that aren't a CIS recommendation on this OS (extra hardening)
        [switch]$CisOnly
    )

    $KnownIds = @($Catalog.controls | ForEach-Object { $_.id })
    $Unknown  = @($Include + $Exclude | Where-Object { $_ -and ($_ -notin $KnownIds) })
    if ($Unknown.Count -gt 0) {
        throw "Unknown control id(s): $($Unknown -join ', ')"
    }

    # Level 2 includes everything in Level 1. Opt-in controls only run when explicitly included.
    @($Catalog.controls | Where-Object {
        ($_.os -contains $Os) -and
        ($_.roles -contains $Role) -and
        ($_.level -le $Level) -and
        ((-not $Platform) -or ($_.platforms -contains $Platform)) -and
        ((-not $CisOnly) -or (Get-CisRef -Control $_ -Os $Os)) -and
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

# Runs a script control's apply or test file. Controls that share a script pass their
# own settings through "parameters", e.g. the SIDs for URA-01 and URA-02.
function Invoke-ControlScript {
    param($Control, $Context, [string]$Stage)
    $ScriptArgs = @{ Context = $Context }
    if ($Control.parameters) { $ScriptArgs.Parameters = $Control.parameters }
    & (Get-ControlScriptPath $Control $Context $Stage) @ScriptArgs
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
            Invoke-ControlScript $Control $Context 'apply' | Out-Null
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
                $Result = Invoke-ControlScript $Control $Context 'test' | Select-Object -Last 1
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

# Runs the selected controls in catalog order. In Test mode, returns one result per
# control (Id, Title, Passed, Detail). Apply mode returns nothing; any error throws instead.
function Invoke-CisBaselineRun {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Apply', 'Test')][string]$Mode,
        [Parameter(Mandatory=$true)][object[]]$Controls,
        [Parameter(Mandatory=$true)]$Context
    )

    $Total = $Controls.Count
    for ($i = 0; $i -lt $Total; $i++) {
        $Control = $Controls[$i]
        if ($Mode -eq 'Apply') {
            Write-Host "[$($i + 1)/$Total] $($Control.id) $($Control.title)"
            # Discard any stray output so Apply mode never returns anything
            Invoke-CisControl -Control $Control -Context $Context | Out-Null
        } else {
            $Result = Test-CisControl -Control $Control -Context $Context
            if ($Result.Passed) {
                Write-Host "[PASS] $($Control.id) $($Control.title)" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] $($Control.id) $($Control.title): $($Result.Detail)" -ForegroundColor Red
            }
            $Result
        }
    }
}

function Get-CisControlById {
    param($Catalog)
    $Lookup = @{}
    foreach ($Control in $Catalog.controls) { $Lookup[$Control.id] = $Control }
    $Lookup
}

# Writes the Test-mode results as JSON evidence, including each control's ATT&CK mappings.
function Export-CisComplianceReport {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Results,
        [Parameter(Mandatory=$true)]$Catalog,
        [Parameter(Mandatory=$true)][string]$Os,
        [Parameter(Mandatory=$true)][int]$Level,
        [ValidateSet('ms', 'dc')][string]$Role = 'ms',
        [Parameter(Mandatory=$true)][string]$Path
    )

    $ById = Get-CisControlById $Catalog
    $Failed = @($Results | Where-Object { -not $_.Passed }).Count
    $Report = [ordered]@{
        catalogVersion = $Catalog.version
        attackVersion  = $Catalog.attackVersion
        benchmark      = $Catalog.benchmarks.$Os
        os             = $Os
        role           = $Role
        level          = $Level
        generatedAt    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        passed         = $Results.Count - $Failed
        failed         = $Failed
        results        = @($Results | ForEach-Object {
            [ordered]@{
                id     = $_.Id
                title  = $_.Title
                passed = [bool]$_.Passed
                detail = $_.Detail
                cis    = @(Get-CisRef -Control $ById[$_.Id] -Os $Os)
                mitre  = @($ById[$_.Id].mitre)
            }
        })
    }
    $Parent = Split-Path -Parent $Path
    if ($Parent -and -not (Test-Path $Parent)) { New-Item -Path $Parent -ItemType Directory -Force | Out-Null }
    ConvertTo-Json -InputObject $Report -Depth 6 | Set-Content -Path $Path -Encoding UTF8
}

# Groups the selected controls by ATT&CK technique. Returns one entry per technique ID with
# the controls that mitigate it and the controls that detect it.
function Get-CisAttackCoverage {
    param([Parameter(Mandatory=$true)][object[]]$Controls)

    $Coverage = @{}
    foreach ($Control in $Controls) {
        foreach ($Mapping in @($Control.mitre)) {
            if (-not $Coverage.ContainsKey($Mapping.id)) {
                $Coverage[$Mapping.id] = [pscustomobject]@{ Id = $Mapping.id; Mitigates = @(); Detects = @() }
            }
            if ($Mapping.relation -eq 'mitigates') {
                $Coverage[$Mapping.id].Mitigates += $Control.id
            } else {
                $Coverage[$Mapping.id].Detects += $Control.id
            }
        }
    }
    $Coverage.Values | Sort-Object Id
}

# Writes an ATT&CK Navigator layer for the selected controls.
# Green = mitigated, blue = detected, teal = both. Comments list the control IDs.
function Export-AttackLayer {
    param(
        [Parameter(Mandatory=$true)][object[]]$Controls,
        [Parameter(Mandatory=$true)]$Catalog,
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Name = "CIS baseline $($Catalog.version) coverage"
    )

    $Colours = @{ mitigates = '#6fcf97'; detects = '#5aa9e6'; both = '#2bb5a8' }
    $Coverage = @(Get-CisAttackCoverage -Controls $Controls)
    $Ids = @($Coverage | ForEach-Object { $_.Id })

    $Techniques = @()
    foreach ($Entry in $Coverage) {
        $Kind = if ($Entry.Mitigates.Count -and $Entry.Detects.Count) { 'both' } elseif ($Entry.Mitigates.Count) { 'mitigates' } else { 'detects' }
        $Notes = @()
        if ($Entry.Mitigates.Count) { $Notes += "Mitigated by: $($Entry.Mitigates -join ', ')" }
        if ($Entry.Detects.Count)   { $Notes += "Detected by: $($Entry.Detects -join ', ')" }
        $Techniques += [ordered]@{
            techniqueID       = $Entry.Id
            color             = $Colours[$Kind]
            comment           = ($Notes -join '. ')
            enabled           = $true
            # Expand parents so mapped sub-techniques are visible in the matrix
            showSubtechniques = [bool]($Ids | Where-Object { $_ -like "$($Entry.Id).*" })
        }
    }
    # Parents of mapped sub-techniques that aren't mapped themselves still need expanding
    foreach ($Parent in @($Ids | Where-Object { $_ -like '*.*' } | ForEach-Object { $_.Split('.')[0] } | Sort-Object -Unique)) {
        if ($Parent -notin $Ids) {
            $Techniques += [ordered]@{ techniqueID = $Parent; enabled = $true; showSubtechniques = $true }
        }
    }

    $Layer = [ordered]@{
        name        = $Name
        versions    = [ordered]@{ attack = $Catalog.attackVersion; navigator = '5.1.0'; layer = '4.5' }
        domain      = 'enterprise-attack'
        description = "Techniques covered by $($Controls.Count) controls from catalog $($Catalog.version)."
        techniques  = $Techniques
        legendItems = @(
            [ordered]@{ label = 'Mitigated by a control'; color = $Colours.mitigates },
            [ordered]@{ label = 'Detected by a control';  color = $Colours.detects },
            [ordered]@{ label = 'Mitigated and detected'; color = $Colours.both }
        )
        hideDisabled = $false
        layout       = [ordered]@{ layout = 'side'; showID = $true; showName = $true }
    }
    $Parent = Split-Path -Parent $Path
    if ($Parent -and -not (Test-Path $Parent)) { New-Item -Path $Parent -ItemType Directory -Force | Out-Null }
    ConvertTo-Json -InputObject $Layer -Depth 6 | Set-Content -Path $Path -Encoding UTF8
}

# Builds a Markdown summary for the GitHub Actions job page. Pass $null for -Results when
# the build stopped before the compliance test ran.
function ConvertTo-CisSummaryMarkdown {
    param(
        [AllowNull()][object[]]$Results,
        [Parameter(Mandatory=$true)][object[]]$Controls,
        [Parameter(Mandatory=$true)]$Catalog,
        [Parameter(Mandatory=$true)][string]$Os,
        # Shown in the heading, e.g. "DC L1"
        [string]$ProfileName
    )

    $ResultById = @{}
    foreach ($Result in @($Results)) { if ($Result) { $ResultById[$Result.id] = $Result } }

    $Heading = "## CIS baseline $($Catalog.version)"
    if ($ProfileName) { $Heading += " ($ProfileName)" }
    $Lines = @($Heading, "")
    if ($Catalog.benchmarks.$Os) { $Lines += "Benchmark: $($Catalog.benchmarks.$Os). Controls marked *Hardening* go beyond it.", "" }
    if ($ResultById.Count -eq 0) {
        $Lines += "> **No compliance results.** The build stopped before the compliance test ran; see the build step log.", ""
    } else {
        $Failed = @($ResultById.Values | Where-Object { -not $_.passed }).Count
        $Lines += "**$($ResultById.Count - $Failed) of $($ResultById.Count) controls passed.**", ""
    }

    $Lines += "| Result | Control | CIS | Title | ATT&CK |", "|---|---|---|---|---|"
    foreach ($Control in $Controls) {
        $Result = $ResultById[$Control.id]
        # Pipes and line breaks in the failure detail would break the table row
        $Detail = "$($Result.detail)" -replace '\|', '\|' -replace '\r?\n', ' '
        $Status = if (-not $Result) { 'Not run' } elseif ($Result.passed) { 'Pass' } else { "**Fail**: $Detail" }
        $Attack = (@($Control.mitre) | ForEach-Object { "$($_.id) ($($_.relation))" }) -join ', '
        $Refs = @(Get-CisRef -Control $Control -Os $Os)
        $Cis = if ($Refs.Count) { $Refs -join ', ' } else { '*Hardening*' }
        $Lines += "| $Status | $($Control.id) | $Cis | $($Control.title) | $Attack |"
    }

    $Coverage = @(Get-CisAttackCoverage -Controls $Controls)
    $Mitigated = @($Coverage | Where-Object { $_.Mitigates.Count }).Count
    $Detected  = @($Coverage | Where-Object { $_.Detects.Count }).Count
    $Lines += "", "**ATT&CK coverage (v$($Catalog.attackVersion)):** $($Coverage.Count) techniques; $Mitigated mitigated, $Detected detected. Download the ``compliance-evidence`` artifact and open ``attack-layer.json`` in the ATT&CK Navigator."
    $Lines -join "`n"
}

Export-ModuleMember -Function Set-RegistryBaseline, Invoke-Native, Assert-CisSupportedRole, Get-CisCatalog,
    Get-CisRef, Select-CisControl, Invoke-CisControl, Test-CisControl, Invoke-CisBaselineRun,
    Export-CisComplianceReport, Get-CisAttackCoverage, Export-AttackLayer, ConvertTo-CisSummaryMarkdown
