# Build the Android app from source

This folder contains the Android WebView shell and a command-line APK build script. The APK is generated locally and is intentionally not tracked in Git.

## Requirements

- Windows 10/11
- Java JDK 17
- Android SDK command-line tools, including `aapt2`, `d8`, `zipalign`, `apksigner`, and Android platform 34
- A working connection to download SDK packages on first setup

## Build from CMD

From the repository root:

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\setup-android-sdk.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File android-app\build-apk.ps1
```

If the SDK is already installed, ensure `ANDROID_HOME` or `ANDROID_SDK_ROOT` points to it before running the second command. The script prints the output path and SHA-256 hash. The output is `android-app\TerminusSecrets.apk`.

## Android Studio alternative

Open `android-app\` as a Gradle project. The source manifest and Java activity are under `app\src\main\`. Use Android Studio's Build > Build APK(s) to produce a debug APK, or use the script above for the command-line signed build.

## Signing key warning

The command-line script creates `android-app\keystore\terminus-release.jks` on first run. Keep this file and its password in a safe place if you want future APKs to upgrade the installed app. Never commit the keystore, passwords, APK, or signing credentials.

The Android shell loads the shared client from the host at `https://HOST:8443/app/`; shared web UI features are served by `server\web\`.
