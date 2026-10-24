<#
.SYNOPSIS
Creates (or with -Remove deletes) the inbound Windows Firewall rule for PortGlass Probe, scoped to
the probe program, its port, and the technician addresses you name.

.EXAMPLE
./scripts/probe-firewall.ps1 -RemoteAddress 10.0.5.0/24
./scripts/probe-firewall.ps1 -RemoteAddress 10.0.5.21,10.0.5.22 -Port 47100
./scripts/probe-firewall.ps1 -Remove
#>
param(
    [string[]]$RemoteAddress,
    [int]$Port = 47100,
    [string]$Program = (Join-Path $env:ProgramFiles 'PortGlass\portglass-probe.exe'),
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -DisplayName 'PortGlass Probe' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) { Write-Host 'Removed the PortGlass Probe firewall rule.'; return }
if (-not $RemoteAddress) {
    throw 'Name the technician addresses allowed to connect, e.g. -RemoteAddress 10.0.5.0/24. Allowing Any is deliberately not the default.'
}
New-NetFirewallRule -DisplayName 'PortGlass Probe' -Description 'Inbound mutually authenticated TLS from PortGlass controllers' `
    -Direction Inbound -Action Allow -Program $Program -Protocol TCP -LocalPort $Port `
    -RemoteAddress $RemoteAddress -Profile Domain, Private | Out-Null
Write-Host "Allowed TCP $Port to $Program from $($RemoteAddress -join ', ') (Domain and Private profiles)."
