#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies or tests the CIS baseline defined in controls/catalog.json.
.DESCRIPTION
    -Mode Apply  hardens the machine using the selected controls.
    -Mode Test   checks every selected control and exits 1 if any fail, which halts the Packer build.
                 -ResultsPath also writes the results as JSON evidence. -ReportOnly exits 0 even when
                 controls fail, so the results can be collected before a separate gate step fails the build.

    Controls are selected by OS, role (ms = member server, dc = domain controller) and CIS level.
    The role must match the machine. Opt-in controls (enabledByDefault = false) only run when
    listed in -Include; any control can be skipped with -Exclude. -CisOnly leaves out the extra
    hardening controls that aren't CIS recommendations for that OS.
.EXAMPLE
    .\Invoke-CisBaseline.ps1 -Mode Apply -Os ws2022 -Role ms -Level 1
.EXAMPLE
    .\Invoke-CisBaseline.ps1 -Mode Test -Os ws2022 -Role dc -Level 1 -Include URA-02
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Apply', 'Test')][string]$Mode,
    [string]$Os = 'ws2022',
    [ValidateSet('ms', 'dc')][string]$Role = 'ms',
    [ValidateSet(1, 2)][int]$Level = 1,
    [string]$Platform,
    [string[]]$Include = @(),
    [string[]]$Exclude = @(),
    [switch]$CisOnly,
    [string]$ResultsPath,
    [switch]$ReportOnly,
    [string]$CatalogPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'controls\catalog.json')
)

$ErrorActionPreference = "Stop"

$LogPath = "$env:SystemRoot\Temp\cis-baseline-$($Mode.ToLower()).log"
Start-Transcript -Path $LogPath -Force | Out-Null

$ExitCode = 0
try {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\CisBaseline.psm1') -Force

    Assert-CisSupportedRole -Role $Role

    $Catalog  = Get-CisCatalog -Path $CatalogPath
    $Controls = @(Select-CisControl -Catalog $Catalog -Os $Os -Role $Role -Level $Level -Platform $Platform -Include $Include -Exclude $Exclude -CisOnly:$CisOnly)
    if ($Controls.Count -eq 0) {
        throw "No controls match OS '$Os', role '$Role', level $Level$(if ($Platform) { ", platform '$Platform'" })."
    }

    $Context = [pscustomobject]@{
        CatalogVersion = $Catalog.version
        ControlsRoot   = $Catalog.Root
        Os             = $Os
        Role           = $Role
        Level          = $Level
    }

    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host " CIS baseline $($Catalog.version): $Mode ($Os, $($Role.ToUpper()) Level $Level, $($Controls.Count) controls)" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    $Results = @(Invoke-CisBaselineRun -Mode $Mode -Controls $Controls -Context $Context)

    Write-Host "=========================================" -ForegroundColor Cyan
    if ($Mode -eq 'Apply') {
        Write-Host "[+] Baseline applied. REBOOT REQUIRED for LSA protection, Schannel and feature removals." -ForegroundColor Green
    } else {
        if ($ResultsPath) {
            Export-CisComplianceReport -Results $Results -Catalog $Catalog -Os $Os -Role $Role -Level $Level -Path $ResultsPath
            Write-Host " Results written to $ResultsPath"
        }
        $FailCount = @($Results | Where-Object { -not $_.Passed }).Count
        if ($FailCount -eq 0) {
            Write-Host " RESULT: ALL $($Controls.Count) CONTROLS PASSED." -ForegroundColor Green
        } else {
            Write-Host " RESULT: $FailCount OF $($Controls.Count) CONTROLS FAILED." -ForegroundColor Red
            if (-not $ReportOnly) { $ExitCode = 1 }
        }
    }
}
catch {
    Write-Host "[!] $Mode failed: $_" -ForegroundColor Red
    $ExitCode = 1
}
finally {
    Stop-Transcript | Out-Null
}

exit $ExitCode
