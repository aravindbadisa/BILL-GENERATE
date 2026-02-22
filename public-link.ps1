$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$frontendDir = Join-Path $repoRoot "frontend"
$backendDir = Join-Path $repoRoot "backend"
$toolsDir = Join-Path $repoRoot "tools"
$cloudflaredExe = Join-Path $toolsDir "cloudflared.exe"

if (-not (Test-Path $frontendDir)) { throw "Missing folder: $frontendDir" }
if (-not (Test-Path $backendDir)) { throw "Missing folder: $backendDir" }

New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

if (-not (Test-Path $cloudflaredExe)) {
  Write-Host "Downloading cloudflared..." -ForegroundColor Cyan
  $url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
  Invoke-WebRequest -Uri $url -OutFile $cloudflaredExe
}

Write-Host "Installing deps + building frontend..." -ForegroundColor Cyan
Set-Location $frontendDir
npm install
$env:VITE_API_URL = ""
npm run build

Write-Host "Installing backend deps..." -ForegroundColor Cyan
Set-Location $backendDir
npm install

Write-Host "Starting backend on http://localhost:5000 ..." -ForegroundColor Cyan
try {
  $p5000 = (netstat -ano | Select-String ":5000" | ForEach-Object { ($_ -split "\s+")[-1] } | Select-Object -First 1)
  if ($p5000) {
    $pidInt = [int]($p5000.Trim())
    Write-Host "Stopping existing process on port 5000 (PID $pidInt)..." -ForegroundColor Yellow
    Stop-Process -Id $pidInt -Force
    Start-Sleep -Seconds 1
  }
} catch {
  # ignore
}

Start-Process powershell -ArgumentList @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-Command",
  "Set-Location '$backendDir'; npm start"
) | Out-Null

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Creating a public link (keeps running; stop with Ctrl+C)..." -ForegroundColor Green
Write-Host "If you close this window, the link will stop working." -ForegroundColor Yellow
Write-Host ""

Set-Location $repoRoot
& $cloudflaredExe tunnel --url http://localhost:5000 --no-autoupdate
