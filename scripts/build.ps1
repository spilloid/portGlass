<#
.SYNOPSIS
Builds PortGlass for Windows x64.

.DESCRIPTION
Stages exist so release binaries can be Authenticode-signed between compiling and zipping: the
published SHA-256 has to cover the signed binaries.
  build    compile dist\portglass.exe, dist\portglass-probe.exe, dist\portglass-relay.exe,
           dist\portglass-mock-target.exe
  package  zip the two product binaries with README, LICENSE, docs, examples and scripts; write .sha256
  all      build then package (default)
CI runs `build`, signs with .github/actions/sign-release, then runs `package`.
Without -Release, builds the debug profile into target\ only (no dist\).

.EXAMPLE
./scripts/build.ps1                     # debug build
./scripts/build.ps1 -Release            # dist\ + zip
./scripts/build.ps1 -Release -Stage build -Tag v0.1.0
#>
param(
    [switch]$Release,
    [ValidateSet('all', 'build', 'package')][string]$Stage = 'all',
    [string]$Tag = ''
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 turns a native tool's stderr (cargo's progress lines) into terminating
# errors under 'Stop'; run native tools under 'Continue' and judge them by exit code instead.
function Invoke-Cargo {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & cargo @args 2>&1 | ForEach-Object { "$_" } | Out-Host } finally { $ErrorActionPreference = $saved }
    if ($LASTEXITCODE -ne 0) { throw "cargo $($args -join ' ') failed" }
}
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
    if (-not $Tag) { $Tag = "v$version" }
    if ($Tag -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Invalid tag' }
    $target = 'x86_64-pc-windows-msvc'

    if (-not $Release) {
        Invoke-Cargo build --workspace --target $target
        Write-Host "Debug binaries: target\$target\debug\"
        return
    }

    $products = @('portglass.exe', 'portglass-probe.exe', 'portglass-relay.exe')
    New-Item -ItemType Directory -Force dist | Out-Null

    if ($Stage -in 'all', 'build') {
        Invoke-Cargo build --workspace --release --target $target
        foreach ($exe in $products + 'portglass-mock-target.exe') {
            Copy-Item "target\$target\release\$exe" dist\ -Force
        }
        Write-Host "Built $Tag into dist\"
    }

    if ($Stage -in 'all', 'package') {
        foreach ($exe in $products) {
            if (-not (Test-Path "dist\$exe")) { throw "dist\$exe is missing - run the build stage first" }
        }
        $asset = "portglass-$Tag-windows-x64.zip"
        $assetPath = Join-Path (Resolve-Path dist) $asset
        if (Test-Path $assetPath) { Remove-Item $assetPath }
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::Open($assetPath, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $files = @()
            $files += $products | ForEach-Object { @{ Path = "dist\$_"; Entry = $_ } }
            $files += @('README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md') | ForEach-Object { @{ Path = $_; Entry = $_ } }
            $files += Get-ChildItem docs -Filter *.md | ForEach-Object { @{ Path = $_.FullName; Entry = "docs/$($_.Name)" } }
            $files += Get-ChildItem examples | ForEach-Object { @{ Path = $_.FullName; Entry = "examples/$($_.Name)" } }
            $files += @('install-probe.ps1', 'uninstall-probe.ps1', 'probe-firewall.ps1', 'diagnostics.ps1', 'verify-signature.ps1') |
                ForEach-Object { @{ Path = "scripts\$_"; Entry = "scripts/$_" } }
            foreach ($f in $files) {
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Resolve-Path $f.Path), "portglass/$($f.Entry)", [IO.Compression.CompressionLevel]::Optimal) | Out-Null
            }
        } finally { $zip.Dispose() }
        $hash = (Get-FileHash $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $asset" | Out-File "$assetPath.sha256" -Encoding ascii
        Write-Output $assetPath
    }
} finally {
    Pop-Location
}
