# Windows, IPv6, HTTPS, clients, and GitHub: complete guide

This guide is written for a Windows 10/11 laptop running Terminus Secrets. Commands are for **PowerShell** unless marked otherwise.

## 1. Clone or update the repository

Install Git for Windows and Python 3.11 or newer. To clone:

```powershell
cd "$env:USERPROFILE\Desktop"
git clone https://github.com/dollax26-official/terminus-secret-chatting.git
cd terminus-secret-chatting
```

If it is already cloned, safely update:

```powershell
cd "$env:USERPROFILE\Desktop\terminus-secret-chatting"
git status
git pull --ff-only origin main
```

Review any local modifications before pulling; do not discard work blindly.

## 2. Install and start the host

```powershell
cd "$env:USERPROFILE\Desktop\terminus-secret-chatting\server"
python -m pip install -r requirements.txt
python host.py --port 8443
```

Keep the terminal open. On first run the host creates runtime data under `server\data\`: SQLite history, TLS certificate/private key, device-enrollment master key, pairing code, and vault passphrase. Back up the database and protect these secrets. The device master key enrolls devices; the vault passphrase derives the encryption key for message history.

In a second PowerShell window, check the local health endpoint:

```powershell
curl.exe -k https://127.0.0.1:8443/api/health
```

Here `-k` is for diagnosis only; it skips normal certificate verification. When pairing clients, compare the SHA-256 certificate fingerprint shown by the client with the fingerprint printed by the host.

## 3. Allow only the HTTPS host port through Windows Firewall

Open **PowerShell as Administrator**:

```powershell
New-NetFirewallRule -DisplayName "Terminus Secrets HTTPS 8443" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8443 -Profile Private,Public
```

For trusted private networks only, use `-Profile Private`. Inspect or remove the rule:

```powershell
Get-NetFirewallRule -DisplayName "Terminus Secrets HTTPS 8443"
Remove-NetFirewallRule -DisplayName "Terminus Secrets HTTPS 8443"
```

A Windows firewall rule only permits traffic through Windows Firewall. It does not create a public IP, configure a router, bypass carrier-grade NAT, or guarantee that your ISP allows inbound connections.

## 4. Understand public IPv4 and IPv6 reachability

Inspect preferred addresses:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object {$_.AddressState -eq "Preferred"} |
  Format-Table InterfaceAlias,IPAddress,PrefixLength
Get-NetIPAddress -AddressFamily IPv6 |
  Where-Object {$_.AddressState -eq "Preferred"} |
  Format-Table InterfaceAlias,IPAddress,PrefixLength
```

IPv4 addresses such as `192.168.x.x`, `10.x.x.x`, and `172.16.x.x` through `172.31.x.x` are private, not directly internet-routable. Direct public IPv4 access generally needs a public IPv4 address and router port forwarding; carrier-grade NAT may prevent it.

Globally routable IPv6 addresses commonly fall within `2000::/3` (often starting with `2` or `3`). IPv6 often avoids NAT port forwarding, but inbound traffic still depends on the router's IPv6 firewall, Windows Firewall, ISP routing/policy, the service listening on the right interfaces, and IPv6 connectivity on the remote network.

Check the address used for outbound IPv6:

```powershell
curl.exe -6 https://api64.ipify.org
```

This reports the outbound address, not proof that inbound connections work. Compare it with the laptop's global IPv6 addresses; VPNs, temporary privacy addresses, and provider routing can explain differences.

### Test from a genuinely external network

Turn Wi-Fi off on a phone and use mobile data, or use another external connection. An IPv6 URL must put the address in brackets:

```text
https://[YOUR_GLOBAL_IPV6]:8443/app/
```

If it times out, verify the exact address, Windows firewall, router IPv6 inbound policy, ISP filtering, port binding, and whether the phone network supports IPv6. Localhost success only proves the service is running locally.

## 5. HTTPS certificate identity

The host creates a self-signed TLS certificate and prints its SHA-256 fingerprint. In each Windows, Android, or browser client:

1. Enter the host URL including `https://` and port `8443`.
2. Check that the client can reach the host.
3. Compare its certificate fingerprint with the one printed in the host terminal.
4. Trust the certificate only if the fingerprints match and you trust the host machine.
5. Pair using the short pairing code or device-enrollment master key.
6. Enter the vault passphrase separately to unlock history.

Do not blindly trust a changed fingerprint. Certificate files are `server\data\cert.pem` and `server\data\key.pem`; regenerating them changes the host identity.

## 6. Connect clients

- **Windows Electron:** use the packaged client under `windows-app\` or `release\` if present; see the main README for building it.
- **Android:** install the APK under `android-app\` or `release\` if present. For a fresh build, follow the README and `tools\setup-android-sdk.ps1`.
- **Browser/PWA:** open `https://HOST:8443/app/` from a browser that can reach the host. Certificate handling varies by browser.
- **Same Wi-Fi:** use the LAN address printed by the host.
- **Different networks:** use globally reachable IPv6, correctly configured public IPv4 forwarding, or a trusted overlay/tunnel. LAN addresses do not work from the public internet.

Pair each client separately. Revoke lost devices through **Host & devices**. Keep the enrollment master key and vault phrase private.

## 7. Optional host-only group-creation key

By default, any paired device can create a named group. To restrict group creation to users who know a separate key, set `TERMINUS_ROOM_ADMIN_KEY` in the same PowerShell session before starting the host:

```powershell
$env:TERMINUS_ROOM_ADMIN_KEY = "replace-with-a-long-random-secret"
cd "$env:USERPROFILE\Desktop\terminus-secret-chatting\server"
python host.py --port 8443
```

Use a long random secret. Do not commit it to Git, paste it into issues, or share screenshots containing it. The browser prompts for the key when creating a group; the server independently validates it and rejects requests that omit or provide the wrong key. The key is sent in the HTTPS request body.

To disable the restriction, stop the host and remove the variable from that PowerShell session:

```powershell
Remove-Item Env:TERMINUS_ROOM_ADMIN_KEY
python host.py --port 8443
```

To configure it persistently for your Windows user, use **Settings → System → About → Advanced system settings → Environment Variables**, add a user variable named `TERMINUS_ROOM_ADMIN_KEY`, then restart PowerShell. Persistent variables are available to processes running as your user, so protect the account.

These secrets have different jobs:
- `server\data\master-key.txt`: enrolls devices.
- `server\data\vault-passphrase.txt`: unlocks/decrypts chat history.
- `TERMINUS_ROOM_ADMIN_KEY`: authorizes group creation only.

This feature currently restricts group creation; rename/delete group-management endpoints are not implemented.

## 8. Safely update or contribute

To update your main checkout:

```powershell
cd "$env:USERPROFILE\Desktop\terminus-secret-chatting"
git status
git pull --ff-only origin main
```

To contribute a change:

```powershell
git switch -c my-change
# edit and test files
python tools\smoke_test.py
git add .
git status
git commit -m "Describe the change"
git push -u origin my-change
```

Then create a pull request on GitHub. Never commit `server\data\`, TLS private keys, master keys, vault phrases, the optional group key, Android signing keystores, or personal tokens. Review staged files before committing.

Run the protocol smoke test from the repository root:

```powershell
python tools\smoke_test.py
```

## 9. Troubleshooting

- **Connection refused on localhost:** start the host, check the port, and inspect terminal errors.
- **Local works, remote times out:** check the global address, router/ISP inbound filtering, Windows Firewall, and remote IPv6 support.
- **Certificate warning:** verify the fingerprint out-of-band; do not blindly bypass identity checks.
- **401 unauthorized:** pair the device again; its token may be missing or revoked.
- **403 creating a group:** if `TERMINUS_ROOM_ADMIN_KEY` is set, enter that group-management key, not the vault phrase or device master key.
- **Messages cannot decrypt:** verify all clients use the same vault passphrase.
- **Git says local changes would be overwritten:** back up or commit them before pulling; avoid `git reset --hard` unless you deliberately want to discard work.
