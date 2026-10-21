# Architecture

Terminus Secrets is intentionally small. There are three moving parts: a host, a shared encrypted web client, and two native shells that host it.

## Components

```text
┌─────────────────────────── Windows laptop ───────────────────────────┐
│                                                                      │
│  ┌─────────────────────┐        ┌──────────────────────────────┐    │
│  │ Electron window     │        │ host.py                      │    │
│  │ (or pywebview)      │        │                              │    │
│  │                     │        │  HTTPS :8443                 │    │
│  │  loopback proxy     │───────▶│  pairing + bearer auth       │    │
│  │  127.0.0.1:8756     │  TLS   │  long-poll /api/sync         │    │
│  │  certificate pin    │        │  SQLite (WAL)                │    │
│  └─────────┬───────────┘        └──────────────┬───────────────┘    │
│            │ WebView2                          │                     │
│  ┌─────────▼───────────┐                       │                     │
│  │ server/web (UI)     │                       │                     │
│  │ AES-256-GCM         │                       │                     │
│  └─────────────────────┘                       │                     │
└────────────────────────────────────────────────┼─────────────────────┘
                                                 │ HTTPS + cert pin
                              ┌──────────────────▼──────────────────┐
                              │ Android WebView shell                │
                              │ server/web + native setup/SSL pin    │
                              └──────────────────────────────────────┘
```

### Host (`server/host.py`)

A single-file Python 3.11+ process using only the standard library plus `cryptography` (for certificate generation). It serves:

- the static web client under `/app/`
- the JSON API under `/api/`
- a self-signed TLS certificate generated on first run

It is a **relay and store**, not a participant. It has no vault key and no decryption code.

### Web client (`server/web/`)

A plain HTML/CSS/JS application with no build step and no external assets. It implements:

- pairing and token storage (`localStorage`)
- PBKDF2 key derivation (WebCrypto)
- AES-256-GCM message encryption/decryption
- long-poll sync, room management, unread state
- PWA manifest and service worker (app shell cache only; API responses are never cached)

The same files are used by the Electron window, the Python/pywebview window, the Android WebView, and a browser tab.

### Windows shell (`windows-app/`)

Two implementations of the same idea:

1. **Electron** (`electron/main.js`): Node `http` server on `127.0.0.1:8756` forwards `/app` and `/api` to the host over HTTPS. Before forwarding, it checks the peer certificate's SHA-256 against the pin saved at setup. The BrowserWindow loads the loopback URL, so WebCrypto runs in a secure context without weakening Chromium's certificate handling.
2. **Python/pywebview** (`app.py`): the same proxy in Python and the same pinned TLS check, with a pywebview window.

The proxy is loopback-only. It never listens on a LAN interface.

### Android shell (`android-app/`)

A Java `Activity` with no AndroidX dependencies:

- setup screen for host URL and fingerprint verification (trust on first use)
- `HttpsURLConnection` probe with a permissive trust manager **only** for `/api/health`
- WebView with JavaScript and DOM storage enabled, mixed content disabled
- `onReceivedSslError` compares the presented certificate to the saved pin and calls `proceed()` only on a match
- external links open in the system browser
- back button navigates WebView history first

The web client then performs the normal pairing/unlock flow.

## Trust boundaries

| Boundary | Protection |
| --- | --- |
| Client → host | TLS 1.2+; self-signed cert pinned by SHA-256 |
| Host at rest | AES-256-GCM ciphertext only; no key material |
| Device → device | Shared vault key derived from the passphrase |
| Pairing | Short-lived code + per-IP rate limit; issues a 256-bit token |
| Token at rest | SHA-256 hash in SQLite |
| Browser storage | Token in `localStorage`; key only in memory |

The host certificate is generated with `BasicConstraints(ca=False)` and SANs for `localhost`, the hostname, `127.0.0.1`, and the primary LAN IP. Clients do not rely on the SANs for identity; they pin the certificate hash. This is why Tailscale/MagicDNS addresses work even though they are not in the SAN list.

## Message format

Client-side plaintext payload:

```json
{"t":"text","b":"the actual message"}
```

Encryption:

```text
key        = PBKDF2-HMAC-SHA256(passphrase, salt, 600000, 32 bytes)
nonce      = 12 random bytes
aad        = "terminus-secrets:v1:" + room_id
ciphertext = AES-256-GCM(key, nonce, plaintext, aad)
```

The API receives base64 `nonce` and `ciphertext`. The host validates lengths and stores bytes. It does not parse the payload.

Binding `room_id` as AAD prevents an attacker with database write access from moving a ciphertext into another room and having it decrypt successfully.

## Vault check

A fresh vault has no way to tell a typo'd passphrase from a correct one. The first client to unlock encrypts the marker `terminus-vault-v1` with the derived key and stores the nonce/ciphertext via `POST /api/vault/check`. Every later client decrypts that blob before loading history. A failure means the passphrase is wrong (or the vault belongs to a different host) and the client refuses to continue.

This is a consistency check, not a password verifier: the host stores only ciphertext, and the check cannot be used to brute-force the passphrase faster than the real messages.

## Sync protocol

`GET /api/sync?after=<last_id>&wait=<seconds>` returns:

```json
{
  "messages": [{"id": 42, "room_id": "general", "device_id": "dev_...", "device_name": "Pixel 9",
                "client_msg_id": "...", "nonce": "...", "ciphertext": "...", "created_at": "..."}],
  "rooms": [{"id": "general", "name": "general"}],
  "devices": [{"id": "dev_...", "name": "Windows desk", "last_seen": "..."}],
  "you": "dev_...",
  "last_id": 42,
  "has_more": false,
  "server_time": "...",
  "vault": {"salt": "...", "iterations": 600000}
}
```

The server holds the request open for up to 25 seconds when there are no new rows, using a condition variable. Clients reconnect immediately after each response. This avoids WebSocket complexity and works through restrictive networks, at the cost of one request per 20 seconds per device.

`client_msg_id` is unique per device, so retries after a lost response are idempotent: the server returns the existing row instead of duplicating it.

## Database

```sql
devices(id TEXT PK, name TEXT, token_hash TEXT UNIQUE, created_at TEXT, last_seen TEXT, revoked INT)
rooms(id TEXT PK, name TEXT, created_at TEXT)
messages(id INTEGER PK AUTOINCREMENT, room_id TEXT, device_id TEXT,
         client_msg_id TEXT, nonce BLOB, ciphertext BLOB, created_at TEXT,
         UNIQUE(device_id, client_msg_id))
meta(key TEXT PK, value TEXT)
```

SQLite is in WAL mode. The database is the entire history; copying it while the host is stopped is a valid backup.

## Design decisions and trade-offs

- **Long-poll instead of WebSocket.** Fewer dependencies, easier proxying, and sufficient for a personal chat. Latency is effectively immediate because the request is already open.
- **One shared vault key instead of per-device ECDH.** Much simpler and works with WebCrypto everywhere. The cost is no forward secrecy and no per-device revocation of *history* access (revoking a token stops future sync, but a device that already cached messages keeps them).
- **Self-signed certificate + pin instead of a local CA.** No certificate installation on every device. The trade-off is a one-time fingerprint comparison.
- **Fixed loopback port 8756 on Windows.** Keeps `localStorage` stable across launches, so the device token survives restarts. Only one copy of the app can run at a time.
- **No message search server-side.** The host cannot read messages, so search would have to happen client-side after decryption.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Host down | Clients show `reconnecting` and retry with backoff; queued sends fail and can be retried by tapping the bubble |
| Host cert rotated | Pin check fails; Windows opens setup, Android refuses SSL until the app data is cleared and the host re-trusted |
| Token revoked | Next sync returns 401; client locks and asks to pair again |
| Wrong passphrase | Vault check fails before history is shown |
| Database copied without passphrase | Ciphertext only; no recovery |
| Disk full | SQLite write fails; API returns 500; client shows a send error |
