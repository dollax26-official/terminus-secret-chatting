# Terminus Secrets feature audit (second pass)

This document separates features present in the shared client from features that still need work. The project is not Discord feature parity.

## Implemented in the current feature branch

- Account sign-up/sign-in using case-insensitive unique usernames and password hashes.
- Device pairing with a pairing code or host master key; per-device revocation.
- Persistent vault passphrase, master key, and pairing code stored under the host data directory. Keep that directory between restarts. If the public IPv6 address changes, update the URL in the client setup screen.
- Server creation, invite-code joins, server switching, owner/admin/member roles, public/private text channels.
- One-to-one and group DMs, text messaging, replies, reactions, pin/unpin, edit/delete own messages.
- Local loaded-history search, typing indicators, unread indicators, mentions/notifications.
- Encrypted small-file attachments and short encrypted voice notes, capped at 40 KB.
- Experimental one-to-one WebRTC voice/video calls and screen sharing, with authenticated signaling and microphone/camera permissions.
- Shared UI served by the host, so the Windows Electron and Android WebView clients use the same web features after the host source is updated.
- Protocol smoke tests cover authentication, duplicate usernames, encrypted messages, DMs/roles, call signaling, and stable pairing credentials across host restarts.

## Limitations and not yet implemented

- Calls use public STUN servers only. There is no TURN relay, so calls may fail on restrictive NATs, carrier networks, or firewalls. Real-world call quality has not been validated.
- Android screen sharing depends on WebView/Android support and is not guaranteed by this implementation.
- Group voice/video calls, persistent voice channels, and conference controls are not implemented.
- This is not a complete Discord clone: custom role/permission builders, moderation/audit logs, server discovery, bots, webhooks, threads/forum channels, rich embeds, and large file uploads are not implemented.
- The app has not been load-tested or benchmarked on every target device. CI builds and protocol tests do not prove that calls work on every network.
- A dynamic IPv6 address cannot be made stable by the pairing code. The code/passphrase persist, but clients must use the host's current reachable address. A stable DNS name/DDNS or a fixed IPv6 assignment is needed to avoid changing URLs.
- The host sees account/server/channel metadata and call signaling/ICE metadata. Chat message bodies and attachments are encrypted client-side; WebRTC media is encrypted by DTLS-SRTP in transit when the peer connection succeeds.

## Validation status

Do not call the branch release-ready until the workflow at the PR head completes successfully and two actual devices have been tested across different networks. A TURN relay and a real-device Android screen-share test are still required for reliable calling.
