# Contributing

## Development setup

```powershell
git clone <your-repo>
cd terminus-secrets

# host
cd server
python -m pip install -r requirements.txt
python host.py --port 8443
```

Open a second terminal for a client.

### Web client

The web UI is plain HTML/CSS/JS. Edit `server/web/` and reload the page; there is no build step. Keep all assets local (no CDN) so the PWA works offline.

### Windows Electron

```powershell
cd windows-app/electron
npm install
npm start
```

### Windows Python client

```powershell
cd windows-app
python -m pip install -r requirements.txt
python app.py
```

### Android

Build without Android Studio:

```powershell
cd android-app
powershell -ExecutionPolicy Bypass -File build-apk.ps1
```

Install on a connected device:

```powershell
adb install -r android-app\TerminusSecrets.apk
```

## Tests

```powershell
python tools/smoke_test.py
```

The test must pass before a PR is merged. It covers pairing, token auth, AES-GCM round-trip, sync paging, vault-check storage, absence of plaintext at rest, and static UI serving.

For UI changes, include a screenshot in the PR and verify:

- desktop width 1440×900
- mobile width 390×844
- empty, loading, error, and long-message states
- keyboard-only navigation

## Style

- Python: standard library first; no framework required for the host.
- JavaScript: no build step, no external dependencies, `const`/`let`, small functions.
- Java: no AndroidX unless there is a clear reason; keep the APK small.
- CSS: design tokens live at the top of `server/web/styles.css`. Keep contrast accessible.

## Security-sensitive changes

Changes to `host.py`, the crypto code in `server/web/app.js`, the Windows proxy, or the Android SSL handler need:

1. a short threat-model note in the PR,
2. a test or a manual verification procedure,
3. no reduction in the default security posture (TLS pinning, 600k PBKDF2, AES-GCM, token hashing).

Never commit:

- `server/data/`
- `android-app/keystore/`
- `*.jks`, `*.keystore`
- `node_modules/`
- `.android-sdk/`
- `.devdata/`, `.shotsdata/`, `.testdata/`

## Pull requests

- Keep commits focused.
- Update `README.md` or `docs/` when behavior changes.
- Describe how you tested on Windows and/or Android.
- By contributing you agree that your changes are licensed under the MIT license.
