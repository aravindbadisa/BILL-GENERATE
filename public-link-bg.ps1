$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$frontendDir = Join-Path $repoRoot "frontend"
$backendDir = Join-Path $repoRoot "backend"
$toolsDir = Join-Path $repoRoot "tools"
$cloudflaredExe = Join-Path $toolsDir "cloudflared.exe"
$runtimeDir = Join-Path $repoRoot ".runtime"
$backendLog = Join-Path $runtimeDir "backend.log"
$backendErr = Join-Path $runtimeDir "backend.err.log"
$tunnelLog = Join-Path $runtimeDir "tunnel.log"
$tunnelErr = Join-Path $runtimeDir "tunnel.err.log"

New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

if (-not (Test-Path $frontendDir)) { throw "Missing folder: $frontendDir" }
if (-not (Test-Path $backendDir)) { throw "Missing folder: $backendDir" }

if (-not (Test-Path $cloudflaredExe)) {
  Write-Host "Downloading cloudflared..." -ForegroundColor Cyan
  $url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
  Invoke-WebRequest -Uri $url -OutFile $cloudflaredExe
}

Write-Host "Updating repo (git pull)..." -ForegroundColor Cyan
Set-Location $repoRoot
git pull

Write-Host "Installing deps + building frontend..." -ForegroundColor Cyan
Set-Location $frontendDir
npm install
$env:VITE_API_URL = ""
npm run build

Write-Host "Installing backend deps..." -ForegroundColor Cyan
Set-Location $backendDir
npm install

Write-Host "Stopping anything on port 5000 (if running)..." -ForegroundColor Cyan
try {
  $p5000 = (netstat -ano | Select-String ":5000" | ForEach-Object { ($_ -split "\s+")[-1] } | Select-Object -First 1)
  if ($p5000) {
    $pidInt = [int]($p5000.Trim())
    Stop-Process -Id $pidInt -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
  }
} catch {
  # ignore
}

Write-Host "Starting backend (background)..." -ForegroundColor Green
Set-Location $backendDir
if (Test-Path $backendLog) { Remove-Item $backendLog -Force }
if (Test-Path $backendErr) { Remove-Item $backendErr -Force }
$backendProc = Start-Process -PassThru -NoNewWindow -FilePath "npm" -ArgumentList @("start") -RedirectStandardOutput $backendLog -RedirectStandardError $backendErr

Start-Sleep -Seconds 2

Write-Host "Starting Cloudflare quick tunnel (background)..." -ForegroundColor Green
Set-Location $repoRoot
if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }
if (Test-Path $tunnelErr) { Remove-Item $tunnelErr -Force }
$tunnelProc = Start-Process -PassThru -NoNewWindow -FilePath $cloudflaredExe -ArgumentList @("tunnel", "--url", "http://localhost:5000", "--no-autoupdate") -RedirectStandardOutput $tunnelLog -RedirectStandardError $tunnelErr

Write-Host ""
Write-Host "Waiting for public URL..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(30)
$publicUrl = $null
while ((Get-Date) -lt $deadline) {
  if (Test-Path $tunnelLog) {
    $text = Get-Content $tunnelLog -Raw -ErrorAction SilentlyContinue
    if ($text) {
      $m = [regex]::Match($text, "https://[a-z0-9-]+\\.trycloudflare\\.com", "IgnoreCase")
      if ($m.Success) { $publicUrl = $m.Value; break }
    }
  }
  Start-Sleep -Milliseconds 400
}

Write-Host ""
if (-not $publicUrl) {
  Write-Host "Could not detect the tunnel URL yet. Open the log:" -ForegroundColor Yellow
  Write-Host "  $tunnelLog" -ForegroundColor Gray
} else {
  Write-Host "Public URL:" -ForegroundColor Green
  Write-Host "  $publicUrl" -ForegroundColor White
  Write-Host ""
  Write-Host "Open it in Chrome. If it shows 'App failed to load', wait 8 seconds and copy the details shown." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Backend log: $backendLog" -ForegroundColor Gray
Write-Host "Backend err: $backendErr" -ForegroundColor Gray
Write-Host "Tunnel log:  $tunnelLog" -ForegroundColor Gray
Write-Host "Tunnel err:  $tunnelErr" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop:" -ForegroundColor Yellow
Write-Host "  Stop-Process -Id $($backendProc.Id),$($tunnelProc.Id) -Force" -ForegroundColor Gray
