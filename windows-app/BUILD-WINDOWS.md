# Build the Windows app from source

This folder contains the Windows client source. Do not download or commit a prebuilt EXE to build it.

## From Command Prompt (CMD)

Install Node.js 22 LTS and Git for Windows, then open CMD in the repository root:

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting"
cd windows-app\electron
npm.cmd install
npx.cmd electron-builder --win portable --publish never
```

The portable executable is created under `windows-app\electron\dist\`. The PowerShell helper also copies it to `windows-app\TerminusSecrets.exe`:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File build-exe.ps1
```

Run that helper from `windows-app\electron\`. Build outputs are ignored by Git; the source, package manifest, lockfile, and build scripts belong in the repository.

## Run without packaging

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting\windows-app\electron"
npm.cmd install
npm.cmd start
```

## Troubleshooting

- If PowerShell blocks `npm.ps1`, use `npm.cmd` and `npx.cmd` from CMD.
- If Electron download fails, retry on a network that can access the configured Electron mirror.
- Do not delete `package-lock.json` to fix install errors; try `npm.cmd ci` after checking Node.js version.
- Never commit `node_modules`, `dist`, config files containing secrets, or the built EXE.
