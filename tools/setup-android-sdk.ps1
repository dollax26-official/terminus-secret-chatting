# Download the Android command-line SDK used by android-app/build-apk.ps1.
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools/setup-android-sdk.ps1

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Sdk = Join-Path $Root ".android-sdk"
$Downloads = Join-Path $Root ".downloads"

New-Item -ItemType Directory -Force -Path $Sdk, $Downloads | Out-Null

$base = "https://mirrors.cloud.tencent.com/AndroidSDK/"
$files = @{
    "build-tools.zip"    = "build-tools_r34-windows.zip"
    "platform-34.zip"    = "platform-34-ext7_r03.zip"
    "platform-tools.zip" = "platform-tools_r34.0.5-windows.zip"
    "cmdline-tools.zip"  = "commandlinetools-win-13114758_latest.zip"
}

foreach ($key in $files.Keys) {
    $target = Join-Path $Downloads $key
    if ((Test-Path $target) -and ((Get-Item $target).Length -gt 1MB)) {
        Write-Host "cached $key"
        continue
    }
    Write-Host "downloading $key"
    curl.exe -L --fail --retry 3 --connect-timeout 30 -o $target ($base + $files[$key])
    if ($LASTEXITCODE -ne 0) { throw "download failed: $($files[$key])" }
}

function Expand-Package($zip, $destination) {
    if (Test-Path $destination) { return }
    Write-Host "extracting $zip"
    $tmp = Join-Path $Downloads ("tmp-" + [guid]::NewGuid().ToString("N"))
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    if ($inner) {
        Move-Item $inner.FullName $destination
    } else {
        Move-Item $tmp $destination
    }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Expand-Package (Join-Path $Downloads "build-tools.zip") (Join-Path $Sdk "build-tools\34.0.0")
Expand-Package (Join-Path $Downloads "platform-34.zip") (Join-Path $Sdk "platforms\android-34")
Expand-Package (Join-Path $Downloads "platform-tools.zip") (Join-Path $Sdk "platform-tools")
Expand-Package (Join-Path $Downloads "cmdline-tools.zip") (Join-Path $Sdk "cmdline-tools\latest")

Write-Host ""
Write-Host "Android SDK ready at $Sdk" -ForegroundColor Green
Write-Host "Build with: powershell -File android-app/build-apk.ps1"
