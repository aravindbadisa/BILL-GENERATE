$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$backendDir = Join-Path $repoRoot "backend"
$frontendDir = Join-Path $repoRoot "frontend"

if (-not (Test-Path $backendDir)) { throw "Missing folder: $backendDir" }
if (-not (Test-Path $frontendDir)) { throw "Missing folder: $frontendDir" }

Write-Host "Starting backend + frontend..." -ForegroundColor Cyan
Write-Host "Backend:  http://localhost:5000" -ForegroundColor Gray
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Gray

try {
  $inUse5000 = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
  if ($inUse5000) {
    Write-Host "Warning: port 5000 is already in use. If backend fails to start, stop the other process first." -ForegroundColor Yellow
  }
} catch {
  # Ignore on older PowerShell / restricted environments.
}

Start-Process powershell -ArgumentList @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-Command",
  "Set-Location '$backendDir'; npm start"
)

Start-Process powershell -ArgumentList @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-Command",
  "Set-Location '$frontendDir'; npm run dev"
)

Write-Host "Done. Two new PowerShell windows opened (backend + frontend)." -ForegroundColor Green

