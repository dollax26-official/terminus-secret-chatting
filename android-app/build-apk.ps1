# Terminus Secrets - build a signed APK from the command line.
# No Gradle, no Android Studio required.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File build-apk.ps1

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Project = Join-Path $Root "app\src\main"
$Build = Join-Path $Root "build"

if ($env:ANDROID_SDK_ROOT) {
    $Sdk = $env:ANDROID_SDK_ROOT
} elseif ($env:ANDROID_HOME) {
    $Sdk = $env:ANDROID_HOME
} else {
    $Sdk = Join-Path (Split-Path -Parent $Root) ".android-sdk"
}

$BuildTools = Join-Path $Sdk "build-tools\36.0.0"
$AndroidJar = Join-Path $Sdk "platforms\android-36\android.jar"

if (-not (Test-Path $AndroidJar)) {
    throw "Android SDK not found at $Sdk. Run tools/setup-android-sdk.ps1 first."
}
if (-not (Test-Path (Join-Path $BuildTools "aapt2.exe"))) {
    throw "build-tools 34.0.0 not found at $BuildTools."
}

$Jdk = $env:JAVA_HOME
if (-not $Jdk) {
    $candidates = Get-ChildItem "C:\Program Files\Eclipse Adoptium", "C:\Program Files\Java" -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName "bin\javac.exe") }
    if ($candidates) { $Jdk = $candidates[0].FullName }
}
if (-not $Jdk) { throw "A JDK (17+) is required. Set JAVA_HOME." }

$env:JAVA_HOME = $Jdk
$Javac = Join-Path $Jdk "bin\javac.exe"
$Keytool = Join-Path $Jdk "bin\keytool.exe"

$Aapt2 = Join-Path $BuildTools "aapt2.exe"
$D8 = Join-Path $BuildTools "d8.bat"
$ZipAlign = Join-Path $BuildTools "zipalign.exe"
$ApkSigner = Join-Path $BuildTools "apksigner.bat"

Write-Host "Terminus Secrets - Android build" -ForegroundColor Cyan
Write-Host "  SDK : $Sdk"
Write-Host "  JDK : $Jdk"

if (Test-Path $Build) { Remove-Item $Build -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Build, (Join-Path $Build "gen"), (Join-Path $Build "classes"), (Join-Path $Build "dex") | Out-Null

# 1. compile resources
Write-Host "[1/6] aapt2 compile"
$resZip = Join-Path $Build "res.zip"
& $Aapt2 compile --dir (Join-Path $Project "res") -o $resZip
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }

# 2. link resources and manifest
Write-Host "[2/6] aapt2 link"
$unsigned = Join-Path $Build "unsigned.apk"
$gen = Join-Path $Build "gen"
$linkArgs = @(
    "link",
    "-o", $unsigned,
    "-I", $AndroidJar,
    "--manifest", (Join-Path $Project "AndroidManifest.xml"),
    "-R", $resZip,
    "--java", $gen,
    "--min-sdk-version", "26",
    "--target-sdk-version", "36",
    "--version-code", "2",
    "--version-name", "1.1",
    "--auto-add-overlay"
)
& $Aapt2 $linkArgs
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

# 3. javac
Write-Host "[3/6] javac"
$classes = Join-Path $Build "classes"
$sourceFiles = @()
$sourceFiles += Get-ChildItem (Join-Path $Project "java") -Recurse -Filter *.java | Select-Object -ExpandProperty FullName
$sourceFiles += Get-ChildItem $gen -Recurse -Filter *.java | Select-Object -ExpandProperty FullName
$javacArgs = @("--release", "11", "-encoding", "UTF-8", "-classpath", $AndroidJar, "-d", $classes) + $sourceFiles
& $Javac $javacArgs
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

# 4. dex
Write-Host "[4/6] d8"
$dexDir = Join-Path $Build "dex"
$classFiles = Get-ChildItem $classes -Recurse -Filter *.class | Select-Object -ExpandProperty FullName
$d8Args = @("--lib", $AndroidJar, "--min-api", "26", "--output", $dexDir) + $classFiles
& $D8 $d8Args
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

$withDex = Join-Path $Build "with-dex.apk"
$addDex = Join-Path (Split-Path -Parent $Root) "tools\add_dex.py"
& python $addDex $unsigned (Join-Path $dexDir "classes.dex") $withDex
if ($LASTEXITCODE -ne 0) { throw "adding classes.dex failed" }

# 5. align
Write-Host "[5/6] zipalign"
$aligned = Join-Path $Build "aligned.apk"
& $ZipAlign -f 4 $withDex $aligned
if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }

# 6. sign
Write-Host "[6/6] apksigner"
$Keystore = if ($env:TERMINUS_KEYSTORE_PATH) { $env:TERMINUS_KEYSTORE_PATH } else { Join-Path $Root "keystore\terminus-release.p12" }
$Pass = $env:TERMINUS_APK_SIGNING_PASSWORD
if (-not $Pass) {
    $securePass = Read-Host "Enter the APK signing password (use the same password for future releases)" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
    try { $Pass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
if ($Pass.Length -lt 12) { throw "Use a signing password with at least 12 characters." }
$env:TERMINUS_APK_SIGNING_PASSWORD = $Pass

if (-not (Test-Path $Keystore)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Keystore) | Out-Null
    $keyArgs = @(
        "-genkeypair", "-v",
        "-keystore", $Keystore,
        "-storetype", "PKCS12",
        "-storepass:env", "TERMINUS_APK_SIGNING_PASSWORD",
        "-keypass:env", "TERMINUS_APK_SIGNING_PASSWORD",
        "-alias", "terminus",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Terminus Secrets, O=Terminus, C=US"
    )
    & $Keytool $keyArgs
    if ($LASTEXITCODE -ne 0) { throw "keytool failed" }
}

$Out = Join-Path $Root "TerminusSecrets.apk"
if (Test-Path $Out) { Remove-Item $Out -Force }
$signArgs = @(
    "sign",
    "--ks", $Keystore,
    "--ks-key-alias", "terminus",
    "--ks-pass", "env:TERMINUS_APK_SIGNING_PASSWORD",
    "--key-pass", "env:TERMINUS_APK_SIGNING_PASSWORD",
    "--out", $Out,
    $aligned
)
& $ApkSigner $signArgs
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }

& $ApkSigner verify --print-certs $Out | Select-Object -First 8

$Hash = (Get-FileHash $Out -Algorithm SHA256).Hash
$Size = [math]::Round((Get-Item $Out).Length / 1MB, 2)
Write-Host ""
Write-Host "APK ready: $Out" -ForegroundColor Green
Write-Host "  size   : $Size MB"
Write-Host "  sha256 : $Hash"
Write-Host "  package: com.terminus.secrets"

