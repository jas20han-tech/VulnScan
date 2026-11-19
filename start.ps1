# Starts the VulnScan full stack:
#   1. Backend API   -> http://localhost:8000
#   2. Vulnerable testbed target -> http://127.0.0.1:8011
#   3. Frontend (Vite dev server) -> http://localhost:5173
#
# Logs are written to .run/*.log and PIDs to .run/*.pid so stop.ps1 can
# clean everything up. Idempotent: re-running just reports already-running
# services instead of starting duplicates.
#
# Usage:  .\start.ps1   (or: powershell -ExecutionPolicy Bypass -File .\start.ps1)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$RunDir = Join-Path $Root ".run"
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

function Out-Status($msg) { Write-Host $msg -ForegroundColor Cyan }
function Out-Running($name) { Write-Host "$name already running." -ForegroundColor Yellow }

function Start-Svc {
    param(
        [string]$Name,
        [string]$File,
        [string[]]$Arguments,
        [string]$WorkDir,
        [int[]]$PortsToClear
    )
    $pidFile = Join-Path $RunDir "$Name.pid"
    if (Test-Path $pidFile) {
        $old = Get-Content $pidFile -ErrorAction SilentlyContinue
        if ($old -and (Get-Process -Id $old -ErrorAction SilentlyContinue)) {
            Out-Running $Name
            return
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
    # Clear any orphan listener on target ports
    if ($PortsToClear) {
        foreach ($pt in $PortsToClear) {
            $listeners = Get-NetTCPConnection -State Listen -LocalPort $pt -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty OwningProcess -Unique
            foreach ($lp in $listeners) {
                if ($lp) {
                    Stop-Process -Id $lp -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    $stdout = Join-Path $RunDir "$Name.log"
    $stderr = Join-Path $RunDir "$Name.err.log"
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -WorkingDirectory $WorkDir `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    $p.Id | Set-Content -Path $pidFile
    Out-Status "$Name started (PID $($p.Id)) -> logs: .run\$Name*.log"
}

# 1. Backend
Start-Svc -Name "backend" -File (Join-Path $Root "backend\.venv\Scripts\python.exe") `
    -Arguments @("-u", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000") `
    -WorkDir (Join-Path $Root "backend") -PortsToClear @(8000)

# 2. Testbed (vulnerable target)
Start-Svc -Name "testbed" -File (Join-Path $Root "backend\.venv\Scripts\python.exe") `
    -Arguments @("-u", "-m", "uvicorn", "testbed_app:app", "--host", "127.0.0.1", "--port", "8011") `
    -WorkDir (Join-Path $Root "testbeds\vulnerable_app") -PortsToClear @(8011)

# 3. Frontend (Vite) - launched directly via node so it is a single stable
#    process (unlike `npm run dev`, which spawns a transient cmd shim and can
#    orphan the real Vite server, making stop.ps1 unreliable).
Start-Svc -Name "frontend" -File "node.exe" `
    -Arguments @((Join-Path $Root "frontend\node_modules\vite\bin\vite.js")) `
    -WorkDir (Join-Path $Root "frontend") -PortsToClear @(5173, 5174)

Write-Host ""
Out-Status "VulnScan stack launching. Give it a few seconds, then open:"
Write-Host "   Frontend: http://localhost:5173" -ForegroundColor Green
Write-Host "   Backend API docs: http://localhost:8000/docs" -ForegroundColor Green
Write-Host "   Testbed: http://127.0.0.1:8011" -ForegroundColor Green
Write-Host ""
Write-Host "Stop everything with:  .\stop.ps1" -ForegroundColor Yellow
