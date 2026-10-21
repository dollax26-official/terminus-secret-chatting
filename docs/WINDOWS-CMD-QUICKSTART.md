# Terminus Secrets — Windows CMD quick start

These instructions are for source code, not prebuilt APK/EXE files. Run commands from Command Prompt unless a line starts with PowerShell.

## 1. Get the source

```bat
cd /d "%USERPROFILE%\Desktop"
git clone https://github.com/dollax26-official/terminus-secret-chatting.git
cd terminus-secret-chatting
```

For an existing checkout, run `git status` first and then `git pull --ff-only origin main` only if you want the main branch. The feature work may be in an open pull request until merged.

## 2. Start the host server

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting\server"
python -m pip install -r requirements.txt
python host.py --port 8443
```

Leave the server terminal open. In a second CMD window, test locally:

```bat
curl.exe -k https://127.0.0.1:8443/api/health
```

Use `-k` only for this local diagnostic. Compare the host's printed SHA-256 TLS fingerprint with each client before trusting it.

## 3. Optional group-management key

In the same CMD session that starts the host, set a separate key before running the server:

```bat
set TERMINUS_ROOM_ADMIN_KEY=replace-with-a-long-random-secret
python host.py --port 8443
```

The variable is scoped to that CMD window. Set it again after opening a new terminal. Never commit the value. This protects group creation, rename and delete endpoints; deleting a group permanently deletes its stored messages. The `general` group cannot be renamed or deleted.

## 4. Build the Windows client

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting\windows-app\electron"
npm.cmd install
npx.cmd electron-builder --win portable --publish never
```

Output: `windows-app\electron\dist\`. See [BUILD-WINDOWS.md](../windows-app/BUILD-WINDOWS.md).

## 5. Build the Android client

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\setup-android-sdk.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File android-app\build-apk.ps1
```

See [BUILD-ANDROID.md](../android-app/BUILD-ANDROID.md). Keep the signing keystore safe and out of Git.

## 6. Verify source changes

```bat
cd /d "%USERPROFILE%\Desktop\terminus-secret-chatting"
python tools\smoke_test.py
git status
```

## Important security boundary

The optional key is a host-side administrative check, not private-room membership. All paired devices can still see the room list and room messages. Do not treat a named group as private until server-side membership and read/write authorization have been implemented and tested.

## Network access

Opening Windows Firewall does not itself create a public IP. Public IPv4 may need router forwarding and a real public IPv4 address. IPv6 access requires a global address, compatible client network, and permissive router and Windows firewall rules. Test from mobile data or another external network. Never share the vault phrase, enrollment master key, admin key, TLS private key, or database backup publicly.
