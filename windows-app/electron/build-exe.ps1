# Terminus Secrets - build the Windows desktop client with Electron.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File build-exe.ps1

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$env:ELECTRON_MIRROR = "https://npmmirror.com/mirrors/electron/"
$env:ELECTRON_BUILDER_BINARIES_MIRROR = "https://npmmirror.com/mirrors/electron-builder-binaries/"

Write-Host "Terminus Secrets - Electron build" -ForegroundColor Cyan
Write-Host "  app : $Root"

if (-not (Test-Path (Join-Path $Root "node_modules\electron"))) {
    Write-Host "[1/3] npm install (downloads the Electron runtime)"
    npm install --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
} else {
    Write-Host "[1/3] npm install (cached)"
}

Write-Host "[2/3] electron-builder (portable .exe)"
npx electron-builder --win portable
if ($LASTEXITCODE -ne 0) { throw "electron-builder failed" }

$Built = Join-Path $Root "dist\TerminusSecrets.exe"
if (-not (Test-Path $Built)) { throw "Build finished but dist\TerminusSecrets.exe was not found." }

$Final = Join-Path (Split-Path -Parent $Root) "TerminusSecrets.exe"
Copy-Item $Built $Final -Force

Write-Host "[3/3] verify"
$Hash = (Get-FileHash $Final -Algorithm SHA256).Hash
$Size = [math]::Round((Get-Item $Final).Length / 1MB, 2)
Write-Host ""
Write-Host "Windows app ready: $Final" -ForegroundColor Green
Write-Host "  size   : $Size MB"
Write-Host "  sha256 : $Hash"
