<#
.SYNOPSIS
Runs the whole PortGlass flow on one PC: a mock printer, a probe allowed to reach only it, and
the controller window.

.DESCRIPTION
Everything is local and throwaway: identities and configs go in a fresh folder under %TEMP%, the
probe listens on 127.0.0.1 only (no firewall prompt), and the mock device listens on
127.0.0.2:18080. Close the PortGlass window to end the demo; the script then stops the probe
and the mock device.

In the window: pick "demo-probe", type 127.0.0.2:18080, press Connect.
Try 127.0.0.2:22 or 10.0.0.1:80 to see the probe refuse unauthorized targets.

.EXAMPLE
./scripts/build.ps1; ./scripts/launch-demo.ps1
#>
param(
    [string]$BinDir = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $BinDir) {
    $BinDir = Join-Path $root 'target\x86_64-pc-windows-msvc\debug'
    if (-not (Test-Path "$BinDir\portglass.exe")) { $BinDir = Join-Path $root 'dist' }
}
foreach ($exe in 'portglass.exe', 'portglass-probe.exe', 'portglass-mock-target.exe') {
    if (-not (Test-Path "$BinDir\$exe")) { throw "$BinDir\$exe not found - run ./scripts/build.ps1 first" }
}
$demo = Join-Path $env:TEMP "portglass-demo-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory $demo | Out-Null
$probeCfg = "$demo\probe\probe.toml"
$ctlCfg = "$demo\controller\controller.toml"

& "$BinDir\portglass-probe.exe" --config $probeCfg init --name demo-probe | Out-Null
(Get-Content $probeCfg -Raw).Replace('listen = "0.0.0.0:47100"', 'listen = "127.0.0.1:47199"') | Set-Content -NoNewline $probeCfg
& "$BinDir\portglass.exe" --config $ctlCfg init --operator "$env:USERNAME" | Out-Null
$ctlFp = & "$BinDir\portglass.exe" --config $ctlCfg fingerprint
$probeFp = & "$BinDir\portglass-probe.exe" --config $probeCfg fingerprint
& "$BinDir\portglass-probe.exe" --config $probeCfg authorize --name "$env:USERNAME" --fingerprint $ctlFp | Out-Null
& "$BinDir\portglass-probe.exe" --config $probeCfg allow --network 127.0.0.2 --ports 18080 --label "MockJet 9000 (demo printer)" | Out-Null
& "$BinDir\portglass.exe" --config $ctlCfg probe add --name demo-probe --address 127.0.0.1:47199 --fingerprint $probeFp | Out-Null

Write-Host "Demo folder: $demo"
$mock = Start-Process "$BinDir\portglass-mock-target.exe" -ArgumentList '--listen', '127.0.0.2:18080' -PassThru -WindowStyle Minimized
$probe = Start-Process "$BinDir\portglass-probe.exe" -ArgumentList '--config', "`"$probeCfg`"", 'run' -PassThru
try {
    Start-Sleep -Seconds 1
    Write-Host 'In the PortGlass window: choose demo-probe, type 127.0.0.2:18080, press Connect.'
    & "$BinDir\portglass.exe" --config $ctlCfg
} finally {
    foreach ($p in $probe, $mock) { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } }
    Write-Host "Demo stopped. Audit logs: $demo\probe\audit.jsonl and $demo\controller\audit.jsonl"
}
