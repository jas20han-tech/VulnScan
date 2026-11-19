# Stops everything started by start.ps1 (backend, testbed, frontend).
#
# Kills the tracked PIDs from .run/*.pid, and as a safety net also stops any
# process currently listening on the three service ports (handles cases where
# a previous run left an orphan behind, e.g. an old Vite server).
#
# Usage:  .\stop.ps1   (or: powershell -ExecutionPolicy Bypass -File .\stop.ps1)

$ErrorActionPreference = "SilentlyContinue"
$Root = $PSScriptRoot
$RunDir = Join-Path $Root ".run"
$Ports = @{ backend = 8000; testbed = 8011; frontend = 5173 }

function Stop-Svc($Name) {
    $pidFile = Join-Path $RunDir "$Name.pid"
    $stopped = @()
    if (Test-Path $pidFile) {
        $id = Get-Content $pidFile
        if ($id -and (Get-Process -Id $id -ErrorAction SilentlyContinue)) {
            Stop-Process -Id $id -Force
            $stopped += $id
        }
        Remove-Item $pidFile -Force
    }
    # Safety net: kill whatever listens on the service port (including orphans).
    $portList = if ($Name -eq "frontend") { @(5173, 5174) } else { @($Ports[$Name]) }
    foreach ($port in $portList) {
        $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($lp in $listener) {
            if ($lp -and $lp -notin $stopped) {
                Stop-Process -Id $lp -Force -ErrorAction SilentlyContinue
                $stopped += $lp
            }
        }
    }

    if ($stopped.Count -gt 0) {
        Write-Host "${Name}: stopped PID(s) $($stopped -join ', ')." -ForegroundColor Green
    } else {
        Write-Host "${Name}: nothing running to stop." -ForegroundColor Yellow
    }
}

Stop-Svc "backend"
Stop-Svc "testbed"
Stop-Svc "frontend"

Write-Host ""
Write-Host "All VulnScan services stopped." -ForegroundColor Cyan
