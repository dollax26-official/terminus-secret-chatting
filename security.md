# Security policy

## Reporting a vulnerability

Open a private security advisory on the repository (Security → Advisories), or contact the maintainer through GitHub. Do not open a public issue for a vulnerability that could expose message contents or device tokens.

Include:

- affected component (host, Electron, Android, web client)
- reproduction steps
- expected vs. observed behavior
- whether message confidentiality, device authentication, or availability is affected

## Guarantees

Terminus Secrets aims to provide:

1. **Confidentiality of message bodies and attachments** against the host process, the network, and a passive observer who does not know the vault passphrase.
2. **Integrity and authenticity of ciphertext** through AES-256-GCM, with the room id bound as additional authenticated data.
3. **Host authentication** through a SHA-256 certificate pin established out of band (the fingerprint printed on the host console).
4. **Per-device authorization** through random bearer tokens stored as hashes.
5. **Local persistence**: the full history is a SQLite database on the host machine.

## Non-goals

- Hiding metadata (room names, device names, timestamps, message sizes, IP addresses) from the host.
- Protecting against a compromised host OS, a compromised client device, or malware with access to the unlocked client.
- Forward secrecy. The vault uses a long-lived key derived from the passphrase.
- Multi-user access control. Every paired device in a vault can read every channel.
- Anonymity. The host sees the IP addresses that connect.
- Recovery. A lost passphrase means the history cannot be decrypted.

## Cryptographic details

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| Key derivation | PBKDF2-HMAC-SHA256 | 600,000 iterations, 16-byte random salt, 32-byte output |
| Message encryption | AES-256-GCM | 96-bit random nonce, 128-bit tag |
| AAD | UTF-8 `terminus-secrets:v1:<room_id>` | binds ciphertext to a room |
| Vault check | AES-256-GCM | marker `terminus-vault-v1`, fixed AAD |
| Device token | 256-bit random (`secrets.token_urlsafe(32)`) | stored as SHA-256 |
| Transport | TLS 1.2+ | self-signed P-256 certificate, SHA-256 pin |
| Pairing code | 32-bit random, 8 hex characters | 8 attempts/minute/IP |

The vault key is a non-extractable `CryptoKey` in the browser. It exists only in the page's memory and is discarded on lock/reload.

## Hardening recommendations

- Delete `server/data/vault-passphrase.txt` after memorizing the phrase.
- Use Tailscale or a tunnel; do not expose port 8443 to the public internet.
- Keep `cert.pem` and `key.pem` private. Rotate them if copied.
- Back up `terminus.db` encrypted, separately from the passphrase.
- Revoke unused devices.
- Use a dedicated laptop account for the host if the machine is shared.
- Keep Python, Electron, and Android system WebView updated.

## Known limitations

- The generated passphrase file sits next to the database by default. Anyone with read access to the data directory can decrypt the history. This is a deliberate usability choice; delete the file to remove it.
- Android's WebView certificate handling calls `proceed()` after a fingerprint match. A compromised WebView or a malicious root certificate installed by the user could interfere; the app does not use the system trust store for the host connection.
- The Windows proxy listens on `127.0.0.1:8756` without authentication. Local processes can reach it, but API calls still require a device token. A local attacker who can read the WebView profile can extract the token; this is equivalent to compromising the user account.
- Notifications are generic and do not include message text, by design.

## Audit status

This project has **not** been independently audited. Treat it as a well-structured personal tool, not a replacement for Signal or an enterprise messenger.
