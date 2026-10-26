#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Unit tests for engine/CisBaseline.psm1. Windows-only commands are mocked,
# so these run anywhere pwsh does (macOS, Linux CI).

BeforeAll {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $RepoRoot 'engine/CisBaseline.psm1') -Force
    $Catalog = Get-CisCatalog -Path (Join-Path $RepoRoot 'controls/catalog.json')

    function New-TestControl {
        param([hashtable]$Overrides = @{})
        $Base = @{
            id = 'TEST-01'; title = 'Test control'; area = 'Test'
            cis = [pscustomobject]@{ ref = 'TBC'; level = 1 }
            os = @('ws2022'); platforms = @('azure'); mitre = @()
            enabledByDefault = $true; requiresReboot = $false
            type = 'registry'; rationale = 'Test'
        }
        foreach ($Key in $Overrides.Keys) { $Base[$Key] = $Overrides[$Key] }
        [pscustomobject]$Base
    }

    $Context = [pscustomobject]@{ CatalogVersion = '9.9.9'; ControlsRoot = $TestDrive; Os = 'ws2022'; Level = 1 }
}

Describe 'Select-CisControl' {
    It 'leaves out opt-in controls by default' {
        $Ids = (Select-CisControl -Catalog $Catalog -Os ws2022).id
        $Ids | Should -Not -Contain 'URA-01'
        $Ids | Should -Contain 'CRED-01'
    }

    It 'adds opt-in controls listed in -Include' {
        (Select-CisControl -Catalog $Catalog -Os ws2022 -Include URA-01).id | Should -Contain 'URA-01'
    }

    It 'removes controls listed in -Exclude' {
        (Select-CisControl -Catalog $Catalog -Os ws2022 -Exclude NET-01).id | Should -Not -Contain 'NET-01'
    }

    It 'throws on an unknown control id' {
        { Select-CisControl -Catalog $Catalog -Os ws2022 -Exclude NOPE-99 } | Should -Throw '*NOPE-99*'
    }

    It 'returns nothing for an OS the catalog does not cover' {
        Select-CisControl -Catalog $Catalog -Os ws2019 | Should -BeNullOrEmpty
    }

    It 'filters by platform when one is given' {
        Select-CisControl -Catalog $Catalog -Os ws2022 -Platform hyperv | Should -BeNullOrEmpty
        Select-CisControl -Catalog $Catalog -Os ws2022 -Platform azure | Should -Not -BeNullOrEmpty
    }

    It 'includes level 1 controls at level 2, but not level 2 controls at level 1' {
        $Mini = [pscustomobject]@{ controls = @(
            (New-TestControl @{ id = 'L1-01' }),
            (New-TestControl @{ id = 'L2-01'; cis = [pscustomobject]@{ ref = 'TBC'; level = 2 } })
        ) }
        (Select-CisControl -Catalog $Mini -Os ws2022 -Level 1).id | Should -Be @('L1-01')
        (Select-CisControl -Catalog $Mini -Os ws2022 -Level 2).id | Should -Be @('L1-01', 'L2-01')
    }
}

Describe 'Invoke-CisControl' {
    It 'writes every registry setting with its kind' {
        Mock -ModuleName CisBaseline Set-RegistryBaseline {}
        $Control = New-TestControl @{ settings = @(
            [pscustomobject]@{ path = 'HKLM:\A'; name = 'One'; value = 1 },
            [pscustomobject]@{ path = 'HKLM:\B'; name = 'Two'; value = 'x'; kind = 'String' }
        ) }
        Invoke-CisControl -Control $Control -Context $Context
        Should -Invoke -ModuleName CisBaseline Set-RegistryBaseline -Times 1 -Exactly -ParameterFilter { $Name -eq 'One' -and $Type -eq 'DWord' }
        Should -Invoke -ModuleName CisBaseline Set-RegistryBaseline -Times 1 -Exactly -ParameterFilter { $Name -eq 'Two' -and $Type -eq 'String' }
    }

    It 'throws on an unknown control type' {
        { Invoke-CisControl -Control (New-TestControl @{ type = 'bogus' }) -Context $Context } | Should -Throw '*unknown type*'
    }
}

Describe 'Test-CisControl' {
    Context 'registry' {
        BeforeAll {
            $Control = New-TestControl @{ settings = @(
                [pscustomobject]@{ path = 'HKLM:\A'; name = 'One'; value = 1 }
            ) }
        }

        It 'passes when the value matches' {
            Mock -ModuleName CisBaseline Get-ItemProperty { [pscustomobject]@{ One = 1 } }
            (Test-CisControl -Control $Control -Context $Context).Passed | Should -BeTrue
        }

        It 'fails and explains why when the value differs' {
            Mock -ModuleName CisBaseline Get-ItemProperty { [pscustomobject]@{ One = 0 } }
            $Result = Test-CisControl -Control $Control -Context $Context
            $Result.Passed | Should -BeFalse
            $Result.Detail | Should -BeLike '*One = 0 (expected 1)*'
        }

        It 'fails when the value is missing' {
            Mock -ModuleName CisBaseline Get-ItemProperty { throw 'not found' }
            (Test-CisControl -Control $Control -Context $Context).Detail | Should -BeLike '*<missing>*'
        }
    }

    Context 'auditpol' {
        BeforeAll {
            $Control = New-TestControl @{ type = 'auditpol'; subcategories = @(
                [pscustomobject]@{ guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; name = 'Logon'; success = $true; failure = $true }
            ) }
        }

        It 'passes when auditpol reports the expected setting' {
            Mock -ModuleName CisBaseline Invoke-Native {
                '', 'Machine Name,Policy Target,Subsystem,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting',
                'VM,System,,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,'
            }
            (Test-CisControl -Control $Control -Context $Context).Passed | Should -BeTrue
        }

        It 'fails when auditpol reports something else' {
            Mock -ModuleName CisBaseline Invoke-Native {
                'Machine Name,Policy Target,Subsystem,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting',
                'VM,System,,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,'
            }
            (Test-CisControl -Control $Control -Context $Context).Detail | Should -BeLike "*Logon is 'Success'*"
        }
    }

    Context 'script' {
        It 'uses the last value the test script returns' {
            Set-Content -Path (Join-Path $TestDrive 'pass.ps1') -Value 'param($Context) "noise"; $Context.CatalogVersion -eq "9.9.9"'
            Set-Content -Path (Join-Path $TestDrive 'fail.ps1') -Value 'param($Context) $false'
            (Test-CisControl -Control (New-TestControl @{ type = 'script'; test = 'pass.ps1' }) -Context $Context).Passed | Should -BeTrue
            (Test-CisControl -Control (New-TestControl @{ type = 'script'; test = 'fail.ps1' }) -Context $Context).Passed | Should -BeFalse
        }
    }
}

Describe 'Invoke-CisBaselineRun' {
    It 'returns one result per control in Test mode' {
        Mock -ModuleName CisBaseline Write-Host {}
        Mock -ModuleName CisBaseline Test-CisControl { [pscustomobject]@{ Id = $Control.id; Passed = ($Control.id -ne 'B-01'); Detail = 'x' } }
        $Controls = @((New-TestControl @{ id = 'A-01' }), (New-TestControl @{ id = 'B-01' }), (New-TestControl @{ id = 'C-01' }))
        $Results = @(Invoke-CisBaselineRun -Mode Test -Controls $Controls -Context $Context)
        $Results.Count | Should -Be 3
        @($Results | Where-Object { -not $_.Passed }).Id | Should -Be 'B-01'
    }

    It 'returns nothing in Apply mode, even if a handler writes output' {
        Mock -ModuleName CisBaseline Write-Host {}
        Mock -ModuleName CisBaseline Invoke-CisControl { 'stray output' }
        Invoke-CisBaselineRun -Mode Apply -Controls @(New-TestControl) -Context $Context | Should -BeNullOrEmpty
    }
}

Describe 'Evidence exports' {
    BeforeAll {
        $Mini = [pscustomobject]@{
            version = '9.9.9'; attackVersion = '16'
            controls = @(
                (New-TestControl @{ id = 'A-01'; mitre = @([pscustomobject]@{ id = 'T1557.001'; relation = 'mitigates' }) }),
                (New-TestControl @{ id = 'B-01'; mitre = @(
                    [pscustomobject]@{ id = 'T1557.001'; relation = 'detects' },
                    [pscustomobject]@{ id = 'T1059'; relation = 'detects' }
                ) }),
                (New-TestControl @{ id = 'C-01'; mitre = @() })
            )
        }
        $Results = @(
            [pscustomobject]@{ Id = 'A-01'; Title = 'A'; Passed = $true;  Detail = '' },
            [pscustomobject]@{ Id = 'B-01'; Title = 'B'; Passed = $false; Detail = 'Key = 0 | expected 1' },
            [pscustomobject]@{ Id = 'C-01'; Title = 'C'; Passed = $true;  Detail = '' }
        )
    }

    Context 'Export-AttackLayer' {
        BeforeAll {
            $LayerPath = Join-Path $TestDrive 'layer.json'
            Export-AttackLayer -Controls $Mini.controls -Catalog $Mini -Path $LayerPath
            $Layer = Get-Content $LayerPath -Raw | ConvertFrom-Json
            $ById = @{}; foreach ($T in $Layer.techniques) { $ById[$T.techniqueID] = $T }
        }

        It 'is a Navigator layer for the catalog ATT&CK version' {
            $Layer.domain | Should -Be 'enterprise-attack'
            $Layer.versions.layer | Should -Be '4.5'
            $Layer.versions.attack | Should -Be '16'
        }

        It 'merges mitigating and detecting controls on one technique' {
            $ById['T1557.001'].color | Should -Be '#2bb5a8'
            $ById['T1557.001'].comment | Should -Be 'Mitigated by: A-01. Detected by: B-01'
        }

        It 'colours detect-only techniques differently' {
            $ById['T1059'].color | Should -Be '#5aa9e6'
        }

        It 'expands the parent of a mapped sub-technique' {
            $ById['T1557'].showSubtechniques | Should -BeTrue
            $ById['T1557'].PSObject.Properties.Name | Should -Not -Contain 'color'
        }
    }

    Context 'Export-CisComplianceReport' {
        It 'counts passes and failures and includes the ATT&CK mappings' {
            $Path = Join-Path $TestDrive 'out/results.json'
            Export-CisComplianceReport -Results $Results -Catalog $Mini -Os ws2022 -Level 1 -Path $Path
            $Report = Get-Content $Path -Raw | ConvertFrom-Json
            $Report.passed | Should -Be 2
            $Report.failed | Should -Be 1
            $Report.catalogVersion | Should -Be '9.9.9'
            ($Report.results | Where-Object id -eq 'B-01').mitre.Count | Should -Be 2
        }
    }

    Context 'ConvertTo-CisSummaryMarkdown' {
        It 'has a row per control and escapes pipes in failure details' {
            $Md = ConvertTo-CisSummaryMarkdown -Results $Results -Controls $Mini.controls -Catalog $Mini
            $Md | Should -BeLike '*2 of 3 controls passed*'
            ($Md -split "`n" | Where-Object { $_ -match '^\| .* \| [A-C]-01 \|' }).Count | Should -Be 3
            $Md | Should -BeLike '*Key = 0 \| expected 1*'
        }

        It 'says so when there are no results' {
            ConvertTo-CisSummaryMarkdown -Results $null -Controls $Mini.controls -Catalog $Mini | Should -BeLike '*No compliance results*'
        }
    }
}
