<#
.SYNOPSIS
Collects PortGlass troubleshooting information. Prints configuration-level facts only: no keys,
no audit log contents, no traffic.

.EXAMPLE
./scripts/diagnostics.ps1
./scripts/diagnostics.ps1 -ProbeConfig "$env:ProgramData\PortGlass\probe.toml" -Target 192.168.1.50:80
#>
param(
    [string]$ProbeConfig = '',
    [string]$Target = ''
)
$ErrorActionPreference = 'Continue'
function Find-Exe($name) {
    foreach ($p in @((Get-Command $name -ErrorAction SilentlyContinue).Source,
                     (Join-Path $env:ProgramFiles "PortGlass\$name"),
                     (Join-Path (Split-Path $PSScriptRoot -Parent) $name),
                     (Join-Path (Split-Path $PSScriptRoot -Parent) "dist\$name"),
                     (Join-Path (Split-Path $PSScriptRoot -Parent) "target\x86_64-pc-windows-msvc\debug\$name"))) {
        if ($p -and (Test-Path $p)) { return $p }
    }
}
Write-Host "== System"
Write-Host "Windows: $([Environment]::OSVersion.VersionString)  PowerShell: $($PSVersionTable.PSVersion)"

foreach ($exe in 'portglass.exe', 'portglass-probe.exe') {
    $path = Find-Exe $exe
    Write-Host "`n== $exe"
    if (-not $path) { Write-Host 'not found'; continue }
    $info = (Get-Item $path).VersionInfo
    $sig = Get-AuthenticodeSignature $path
    Write-Host "Path: $path"
    Write-Host "Version: $($info.FileVersion)  Signature: $($sig.Status) $($sig.SignerCertificate.Subject)"
}

$ctl = Find-Exe 'portglass.exe'
if ($ctl) {
    Write-Host "`n== Controller diag"
    & $ctl diag
}

$probe = Find-Exe 'portglass-probe.exe'
if ($probe) {
    Write-Host "`n== Probe"
    $pargs = @()
    if ($ProbeConfig) { $pargs += '--config', $ProbeConfig }
    & $probe @pargs check-config
    if ($Target) { & $probe @pargs diag --target $Target }
    Get-Process portglass-probe -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Running: pid $($_.Id)" }
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -eq 'portglass-probe' } |
        ForEach-Object { Write-Host "Listening: $($_.LocalAddress):$($_.LocalPort)" }
    Get-NetFirewallRule -DisplayName 'PortGlass Probe' -ErrorAction SilentlyContinue | ForEach-Object {
        $f = $_ | Get-NetFirewallAddressFilter
        Write-Host "Firewall rule: enabled=$($_.Enabled) remote=$($f.RemoteAddress -join ',')"
    }
}

Write-Host "`n== Session browser profiles"
$profiles = Join-Path $env:LOCALAPPDATA 'PortGlass\browser-sessions'
$count = @(Get-ChildItem $profiles -Directory -ErrorAction SilentlyContinue).Count
Write-Host "$count left in $profiles (should be 0 when no session is open)"
