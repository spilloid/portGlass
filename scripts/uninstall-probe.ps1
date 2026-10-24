<#
.SYNOPSIS
Removes PortGlass Probe: binary, Start menu shortcut, firewall rule, and (unless -KeepConfig)
its configuration, identity and audit log.
#>
param([switch]$KeepConfig)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator.'
}
Get-Process portglass-probe -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Stopping running probe (pid $($_.Id)); its sessions end."
    Stop-Process -Id $_.Id -Force
}
Get-NetFirewallRule -DisplayName 'PortGlass Probe' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\PortGlass Probe.lnk') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramFiles 'PortGlass\portglass-probe.exe') -ErrorAction SilentlyContinue
$bin = Join-Path $env:ProgramFiles 'PortGlass'
if ((Test-Path $bin) -and -not (Get-ChildItem $bin)) { Remove-Item $bin }
$data = Join-Path $env:ProgramData 'PortGlass'
if ($KeepConfig) {
    Write-Host "Kept $data"
} elseif (Test-Path $data) {
    Remove-Item $data -Recurse -Force
    Write-Host "Removed $data (configuration, identity, audit log)"
}
Write-Host 'PortGlass Probe removed.'
