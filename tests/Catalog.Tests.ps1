#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Checks that controls/catalog.json is valid before it ever reaches a build VM.

BeforeAll {
    $RepoRoot    = Split-Path -Parent $PSScriptRoot
    $CatalogPath = Join-Path $RepoRoot 'controls/catalog.json'
    $SchemaPath  = Join-Path $RepoRoot 'controls/catalog.schema.json'
    $CatalogJson = Get-Content -Path $CatalogPath -Raw
    $Catalog     = $CatalogJson | ConvertFrom-Json
}

Describe 'Controls catalog' {
    It 'matches the JSON schema' {
        Test-Json -Json $CatalogJson -SchemaFile $SchemaPath | Should -BeTrue
    }

    It 'has unique control ids' {
        $Duplicates = $Catalog.controls.id | Group-Object | Where-Object Count -gt 1
        $Duplicates | Should -BeNullOrEmpty
    }

    It 'has a script file for every apply/test path' {
        $ControlsRoot = Split-Path -Parent $CatalogPath
        foreach ($Control in $Catalog.controls | Where-Object type -eq 'script') {
            Join-Path $ControlsRoot $Control.apply | Should -Exist -Because "$($Control.id) apply script"
            Join-Path $ControlsRoot $Control.test  | Should -Exist -Because "$($Control.id) test script"
        }
    }

    It 'has no unused files in controls/scripts' {
        $ControlsRoot = Split-Path -Parent $CatalogPath
        $Referenced = $Catalog.controls | Where-Object type -eq 'script' | ForEach-Object { $_.apply; $_.test } |
            ForEach-Object { Split-Path -Leaf $_ }
        $OnDisk = Get-ChildItem -Path (Join-Path $ControlsRoot 'scripts') -Filter *.ps1 | ForEach-Object Name
        $OnDisk | Where-Object { $_ -notin $Referenced } | Should -BeNullOrEmpty
    }

    It 'has controls enabled by default for both roles on every OS with a benchmark' {
        foreach ($Os in $Catalog.benchmarks.PSObject.Properties.Name) {
            foreach ($Role in 'ms', 'dc') {
                $Catalog.controls | Where-Object { $_.os -contains $Os -and $_.roles -contains $Role -and $_.enabledByDefault } |
                    Should -Not -BeNullOrEmpty -Because "the $Os $Role profile needs controls"
            }
        }
    }

    It 'only gives CIS refs for OSes the control runs on and that have a benchmark' {
        $Benchmarked = @($Catalog.benchmarks.PSObject.Properties.Name)
        foreach ($Control in $Catalog.controls | Where-Object cis) {
            foreach ($Os in $Control.cis.PSObject.Properties.Name) {
                $Control.os | Should -Contain $Os -Because "$($Control.id) has a $Os ref"
                $Benchmarked | Should -Contain $Os -Because "$($Control.id) has a $Os ref"
            }
        }
    }

    It 'every OS a control lists has a benchmark' {
        $Benchmarked = @($Catalog.benchmarks.PSObject.Properties.Name)
        $Catalog.controls.os | Sort-Object -Unique | Where-Object { $_ -notin $Benchmarked } | Should -BeNullOrEmpty
    }

    It 'rejects a malformed CIS ref or a missing level' {
        $Copy = $CatalogJson | ConvertFrom-Json
        $Copy.controls[0] | Add-Member -NotePropertyName cis -NotePropertyValue ([pscustomobject]@{ ws2022 = @('TBC') }) -Force
        Test-Json -Json ($Copy | ConvertTo-Json -Depth 10) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue | Should -BeFalse
        $Copy = $CatalogJson | ConvertFrom-Json
        $Copy.controls[0].PSObject.Properties.Remove('level')
        Test-Json -Json ($Copy | ConvertTo-Json -Depth 10) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue | Should -BeFalse
    }

    It 'gives every member-server-only user rights control a DC counterpart' {
        $Ura = $Catalog.controls | Where-Object { $_.area -eq 'User rights' }
        ($Ura | Where-Object { $_.roles -contains 'ms' }) | Should -Not -BeNullOrEmpty
        ($Ura | Where-Object { $_.roles -contains 'dc' }) | Should -Not -BeNullOrEmpty
    }

    It 'rejects a control without roles or with an unknown role' {
        $Copy = $CatalogJson | ConvertFrom-Json
        $Copy.controls[0].roles = @('workstation')
        Test-Json -Json ($Copy | ConvertTo-Json -Depth 10) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue | Should -BeFalse
        $Copy.controls[0].PSObject.Properties.Remove('roles')
        Test-Json -Json ($Copy | ConvertTo-Json -Depth 10) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue | Should -BeFalse
    }
}

Describe 'ATT&CK mappings' {
    BeforeAll {
        # Every technique the catalog uses, checked by hand against attack.mitre.org.
        # A new mapping must be added here too, which catches typos in technique IDs.
        $ReviewedTechniques = @{
            'T1003.001' = 'OS Credential Dumping: LSASS Memory'
            'T1003.005' = 'OS Credential Dumping: Cached Domain Credentials'
            'T1053.002' = 'Scheduled Task/Job: At'
            'T1021.001' = 'Remote Services: Remote Desktop Protocol'
            'T1021.002' = 'Remote Services: SMB/Windows Admin Shares'
            'T1059'     = 'Command and Scripting Interpreter'
            'T1059.001' = 'Command and Scripting Interpreter: PowerShell'
            'T1068'     = 'Exploitation for Privilege Escalation'
            'T1078'     = 'Valid Accounts'
            'T1087.001' = 'Account Discovery: Local Account'
            'T1098'     = 'Account Manipulation'
            'T1110'     = 'Brute Force'
            'T1110.002' = 'Brute Force: Password Cracking'
            'T1135'     = 'Network Share Discovery'
            'T1136'     = 'Create Account'
            'T1210'     = 'Exploitation of Remote Services'
            'T1550.002' = 'Use Alternate Authentication Material: Pass the Hash'
            'T1557'     = 'Adversary-in-the-Middle'
            'T1557.001' = 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
            'T1562.010' = 'Impair Defenses: Downgrade Attack'
        }

        function Test-CatalogVariant {
            param([scriptblock]$Change)
            $Copy = $CatalogJson | ConvertFrom-Json
            & $Change $Copy.controls[0]
            Test-Json -Json ($Copy | ConvertTo-Json -Depth 10) -SchemaFile $SchemaPath -ErrorAction SilentlyContinue
        }
    }

    It 'only uses reviewed technique IDs' {
        $Used = $Catalog.controls | ForEach-Object { $_.mitre } | ForEach-Object { $_.id } | Sort-Object -Unique
        $Used | Where-Object { -not $ReviewedTechniques.ContainsKey($_) } | Should -BeNullOrEmpty
    }

    It 'records the ATT&CK version' {
        $Catalog.attackVersion | Should -Not -BeNullOrEmpty
    }

    It 'rejects an unknown relation' {
        Test-CatalogVariant { param($C) $C.mitre = @([pscustomobject]@{ id = 'T1003.001'; relation = 'prevents' }) } | Should -BeFalse
    }

    It 'rejects a malformed technique ID' {
        Test-CatalogVariant { param($C) $C.mitre = @([pscustomobject]@{ id = 'T13'; relation = 'mitigates' }) } | Should -BeFalse
    }

    It 'rejects a mapping without a relation' {
        Test-CatalogVariant { param($C) $C.mitre = @([pscustomobject]@{ id = 'T1003.001' }) } | Should -BeFalse
    }
}
