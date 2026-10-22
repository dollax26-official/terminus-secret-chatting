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
    "cmdline-tools.zip" = "commandlinetools-win-13114758_latest.zip"
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

Expand-Package (Join-Path $Downloads "cmdline-tools.zip") (Join-Path $Sdk "cmdline-tools\latest")

$sdkmanager = Join-Path $Sdk "cmdline-tools\latest\bin\sdkmanager.bat"
if (-not (Test-Path $sdkmanager)) { throw "Android sdkmanager was not found after extraction." }
Write-Host "Accepting Android SDK licenses..."
"y" | & $sdkmanager "--sdk_root=$Sdk" --licenses
if ($LASTEXITCODE -ne 0) { throw "Could not accept Android SDK licenses." }
Write-Host "Installing Android 16 platform and build tools..."
& $sdkmanager "--sdk_root=$Sdk" "platforms;android-36" "build-tools;36.0.0" "platform-tools"
if ($LASTEXITCODE -ne 0) { throw "Android 16 SDK installation failed. Check network access to Google Android SDK repositories." }

Write-Host ""
Write-Host "Android SDK ready at $Sdk" -ForegroundColor Green
Write-Host "Build with: powershell -File android-app/build-apk.ps1"
