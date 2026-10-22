# Terminus Secrets — Feature and Quality Audit

Audit target: branch `feature/standalone-host-manager-app`, including the host-manager packaging and master-key channel-access changes.

This is a source and CI audit, **not a claim that every UI path has been manually tested on a physical Android phone and Windows desktop**.

## Implemented in source

- **Accounts:** sign-up/sign-in is required before pairing. Usernames are unique case-insensitively per host; display names can be reused. Passwords are stored as PBKDF2-HMAC-SHA256 hashes. Multiple devices can still be paired to the same account.
- **Saved hosts and reconnect:** a sidebar lets users save up to 20 HTTPS host addresses. Reconnecting requires account sign-in, pairing code (or master key for enrollment), and vault phrase. A stale saved address must be updated if the host's public address changes.
- **Stable host identity:** the vault phrase, pairing code, master key, TLS certificate, database, and settings are stored under the persistent host data folder. Preserve that folder across app updates and network changes to keep credentials stable.
- **Servers and channels:** create/join/invite, edit/delete servers, create/edit/delete channels, categories, private channels, server owner/admin/member roles, and private-channel membership controls.
- **Master-key administration:** a device enrolled with the host master key is marked as a host administrator for private-channel access management, even if its account is only a normal server member. The host checks this permission server-side; ordinary members remain denied. The shared UI exposes this access-management action on both Android and Windows.
- **Direct messages:** one-to-one and group DMs, with server-side conversation-membership checks.
- **Message tools:** replies, reactions, pins, edit/delete, typing indicators, unread counts, search over loaded history, and mention highlighting.
- **Notifications:** Windows/browser notifications and an Android native notification bridge are implemented, but these are not a remote push service and may be missed when the app is suspended, terminated, or throttled by the operating system.
- **Photos/files and voice notes:** host settings can disable these capabilities. Attachments and voice-note payloads are encrypted on the sending client; ordinary attachments are size-limited and voice notes are short.
- **Voice/video calls and screen sharing:** one-to-one DM calls use WebRTC signaling; screen sharing depends on browser/Electron/Android WebView support and user permission. No bundled TURN relay is configured, so calls can fail on restrictive NATs, mobile carriers, or firewalls.
- **Standalone host manager:** the GUI configures the HTTPS port and optional public URL, toggles photos/voice messages/voice calls/video calls/screen sharing, estimates RAM, displays persistent credentials locally, and starts/stops the host. CI packages `TerminusSecretsHostManager.exe` and `TerminusSecretsHost.exe`.
- **Scroll behavior:** the shared CSS gives the connection screen, channel sidebar, dialogs, and message timeline constrained scroll areas. The native manager uses a scrollable canvas and wheel-event handling. Regression scripts verify source invariants, but manual touchpad/touch testing is still required.

## Network and credential caveats

- Keeping the persistent data directory preserves the vault phrase and pairing code. It does **not** preserve a public IPv6 address.
- A global IPv6 address alone does not guarantee inbound reachability; the carrier/router, local firewall, and network must allow the configured port.
- Automatic reconnection after an address change needs a stable hostname/dynamic DNS or another reachable rendezvous mechanism. Credentials cannot discover a new address by themselves.
- Keep the vault phrase and master key private. Do not post them in logs, screenshots, or public issues.

## UI review basis

The shared client was reviewed using the targeted approach from [UI Guides & Agent Rules](https://github.com/strongeron/ui-guides-agent-rules), whose README recommends searching its principle index and fetching only the relevant rules instead of loading the full corpus. Applicable surfaces here include scroll overflow, accessible forms and recoverable errors, semantic buttons, keyboard focus, responsive/mobile hit targets, dialogs, media capability feedback, reduced motion, and performance. The ongoing requirements are recorded in `AGENTS.md` and `docs/ui-quality-checklist.md`.

## Automated validation

The CI workflow runs:
- `python tools/smoke_test.py` for account uniqueness, reusable display names, pairing, encrypted message round-trips, server/channel access, DMs, call signaling, ciphertext-at-rest behavior, and persistent credentials;
- Python compilation for the host and GUI manager;
- scroll regression source checks;
- Node syntax checks for the shared client and Windows Electron shell;
- Windows client, Android APK, and standalone Windows host-manager packaging.

A successful workflow means these automated checks and packaging steps passed. It does not prove that every call works over the public internet, that screen capture works on every Android WebView, or that every visual interaction is perfect on every device.

## Approximate resource use on an Intel Core i5 12th-generation laptop, RTX 3050 4 GB VRAM, and 5 GB system RAM

These are **rough planning estimates**, not measurements from that machine. The host manager's RAM bar is not a live process monitor and does not enforce a hard cap. Estimates are for the laptop's Python host plus a Windows client; the Android client's UI memory is used on the phone.

| Workload | Approximate CPU usage | Approximate Terminus RAM on laptop | RTX 3050 usage |
|---|---:|---:|---:|
| Host idle, no Windows client | 0–3% | 100–300 MB | 0% or near 0% |
| Text chat + Windows client | 2–10% in bursts | 400–900 MB | 0–3% |
| One voice call | 5–20% | 600 MB–1.3 GB | 0–5% |
| One video call | 10–35% | 900 MB–1.8 GB | 5–25% if hardware acceleration is used |
| Video call + screen share | 15–45% | 1.2–2.4 GB | 5–30%, depending on encode/decode acceleration |
| Several clients with active media | 20–70%+ | 2–4.5 GB | 5–40%, depending on active video |

CPU figures are approximate whole-CPU usage, not a benchmark; codec and driver behavior can change them substantially. With only 5 GB of physical RAM, **do not treat 4–5 GB as a safe app budget**: Windows and background applications need memory too. Keep the host plus Windows client near text-chat/light-use workloads, limit concurrent media sessions, close heavy applications, and monitor Task Manager. The app currently does not enforce a hard RAM limit.

## Known gaps — not Discord feature parity

- No group voice/video rooms or push-to-talk.
- No bundled TURN relay; peer-to-peer calls can fail on restrictive networks.
- No reliable automatic discovery when the host's public IPv6 address changes.
- Android screen sharing is platform/WebView-dependent.
- Notifications are best-effort local/browser/native notifications, not guaranteed push delivery while the app is fully suspended.
- No physical-device test is represented by source checks alone. Manual Windows and Android testing, including actual media calls and reconnecting after network changes, remains necessary.
