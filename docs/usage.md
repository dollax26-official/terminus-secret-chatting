# Using Terminus Secrets

## First run on the laptop

```powershell
cd server
python -m pip install -r requirements.txt
python host.py
```

The console prints:

```text
This laptop :  https://127.0.0.1:8443/app/
Network     :  https://192.168.1.42:8443/app/
Pairing code:  A1B2-C3D4
Vault phrase:  vgudo-czqgb-kxvpw-slilj
```

The vault phrase and pairing code are also written to:

- `server/data/vault-passphrase.txt`
- `server/data/pairing-code.txt`

The pairing code changes every time the host restarts. The vault phrase stays the same; it is the key to your history.

## Pairing a device

1. Open the client.
2. Enter the host URL.
3. Verify the certificate fingerprint against the host console (run `curl -k https://127.0.0.1:8443/api/health` on the host to print it again).
4. Enter the pairing code.
5. Enter the vault passphrase.
6. Give the device a name you will recognize later (`Work laptop`, `Pixel 9`).

Each device gets its own token. You can pair a new device at any time without touching the others.

## Sending messages

- Type in the composer and press **Enter**.
- **Shift+Enter** inserts a newline.
- Links beginning with `http://` or `https://` become clickable.
- If a send fails, the bubble is outlined in red. Tap/click it to retry; the same `client_msg_id` is reused, so retries never duplicate.
- If you scroll up while new messages arrive, a **↓ new** pill appears. Click it to jump to the latest.

## Channels

Click **+** in the sidebar, name the channel, and press **Create channel**. Channel names are metadata visible to the host; message contents are not.

Unread counts appear next to channels you are not viewing. The window title shows the total unread count.

## Devices and revocation

Open **Host & devices**:

- **Certificate SHA-256** — the exact host identity this client trusts.
- **Copy fingerprint** — puts the colon-separated hash on the clipboard.
- **Paired devices** — name, last-seen time, and a **REVOKE** button for other devices.
- **Enable desktop notifications** — opt-in; notifications never contain message text.
- **Change host** — only shown in the Windows loopback client.
- **Lock & forget this device** — removes the token and key from this client, then reloads.

Revoking a device stops future sync immediately. It does not erase messages that device already downloaded.

## Backups

The entire history is `server/data/terminus.db`. Stop the host, copy the file (and the `-wal`/`-shm` files if present), and store the copy somewhere safe.

A backup without the vault passphrase is useless. Store the phrase separately from the database.

## Moving to a new laptop

1. Stop the old host.
2. Copy the whole `server/data/` directory to the new laptop.
3. Install Python and `cryptography` on the new laptop.
4. Start `host.py` on the same port.
5. Clients will see a new certificate (the old one is tied to the old machine only if you did not copy `cert.pem`/`key.pem`; copying the whole `data/` directory preserves it).
6. If the certificate changed, re-trust the new fingerprint.

## Recovering from a lost passphrase

There is no recovery. The host stores ciphertext and has no key. If you have a client that is still unlocked, you can read the history there, but the passphrase itself cannot be extracted from the key.

This is the intended trade-off: no recovery backdoor.

## Android notes

- The app is a WebView shell; it needs a network connection to the host. It does not cache message history locally beyond the current WebView session.
- The host certificate pin is stored in app storage. Clearing app data removes the pin and the device token; you will pair again.
- Notifications are not implemented natively; the web client's notification permission works inside the WebView on Android 13+ if the system grants it.
- If the keyboard covers the composer, the activity uses `adjustResize`; rotate or scroll if an older keyboard still overlaps.

## Windows notes

- The Electron app uses a fixed loopback port `8756`. Only one copy can run.
- `%APPDATA%\TerminusSecrets\config.json` stores the host URL, certificate pin, and host name. It does not store the passphrase or device token (those live in the WebView profile).
- Delete `config.json` or run `TerminusSecrets.exe --setup` to reconnect to a different host.
- `%APPDATA%\TerminusSecrets\app.log` (Python) and `electron.log` (Electron) contain diagnostics, never message content.

## Performance

- Sync is a long-poll every 20 seconds plus an immediate request after each send. Latency is typically under a second on LAN.
- History loads in pages of 200 messages; the client keeps up to the last fetched page in memory and renders only the current channel.
- PBKDF2 600k takes roughly 0.3–1.5 seconds on a modern laptop and 1–4 seconds on a mid-range phone. It runs once per unlock, not per message.

## Keyboard and accessibility

- `Tab` moves through channels, composer, and dialogs.
- `Escape` closes the mobile drawer and dialogs.
- `aria-live` announces new messages and errors.
- Reduced-motion preferences disable transitions.
- Buttons have visible focus rings and labels.
