<#
.SYNOPSIS
Installs PortGlass Probe for an administrator-approved deployment.

.DESCRIPTION
- Copies portglass-probe.exe to %ProgramFiles%\PortGlass\.
- Creates %ProgramData%\PortGlass\ readable only by Administrators, SYSTEM and -RunAsUser, and
  initializes the probe's configuration and identity there.
- Adds a Start menu shortcut "PortGlass Probe" that opens the visible console.
- Registers NOTHING to start automatically: no service, no scheduled task, no Run key.

Run from an extracted release folder, as Administrator. Firewall: see probe-firewall.ps1.

.EXAMPLE
./scripts/install-probe.ps1 -Name front-office
#>
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$RunAsUser = "$env:USERDOMAIN\$env:USERNAME",
    [string]$Source = ''
)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator (it writes to Program Files and ProgramData).'
}
if (-not $Source) {
    $here = Split-Path $PSScriptRoot -Parent
    $Source = @("$here\portglass-probe.exe", "$here\dist\portglass-probe.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Source -or -not (Test-Path $Source)) { throw 'portglass-probe.exe not found; pass -Source' }

$sig = Get-AuthenticodeSignature $Source
if ($sig.Status -ne 'Valid') {
    Write-Warning "portglass-probe.exe is not validly signed ($($sig.Status)). Continue only with a build you trust."
}

$bin = Join-Path $env:ProgramFiles 'PortGlass'
$data = Join-Path $env:ProgramData 'PortGlass'
New-Item -ItemType Directory -Force $bin, $data | Out-Null
Copy-Item $Source "$bin\portglass-probe.exe" -Force

# ProgramData inherits "Users: read" by default; the probe's private key must not.
icacls $data /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${RunAsUser}:(OI)(CI)M" | Out-Null

$config = Join-Path $data 'probe.toml'
if (Test-Path $config) {
    Write-Host "Keeping existing configuration $config"
} else {
    & "$bin\portglass-probe.exe" --config $config init --name $Name
}

$shortcutDir = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut((Join-Path $shortcutDir 'PortGlass Probe.lnk'))
$lnk.TargetPath = "$bin\portglass-probe.exe"
$lnk.Arguments = "--config `"$config`" run"
$lnk.WorkingDirectory = $data
$lnk.Description = 'PortGlass Probe - forwards authorized TCP sessions to approved destinations'
$lnk.Save()

Write-Host ''
Write-Host "Installed. Next, as an administrator of this probe:"
Write-Host "  portglass-probe --config `"$config`" authorize --name <technician> --fingerprint <sha256:...>"
Write-Host "  portglass-probe --config `"$config`" allow --network <address> --ports 80,443 --label <label>"
Write-Host "  ./scripts/probe-firewall.ps1 -RemoteAddress <technician addresses>"
Write-Host "Start it from the Start menu (PortGlass Probe). It does not start automatically."
