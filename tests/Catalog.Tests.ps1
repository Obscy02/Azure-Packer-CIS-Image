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

    It 'has at least one control enabled by default for ws2022' {
        $Catalog.controls | Where-Object { $_.os -contains 'ws2022' -and $_.enabledByDefault } | Should -Not -BeNullOrEmpty
    }
}
