# Terminus Secrets — Feature and Quality Audit

Audit target: `main` at `189547216ba1d3cdb51cc78cbba378c5927e12a3` (2026-10-22).

This is a source and CI audit, not a claim that every UI path has been manually tested on a physical Android phone and Windows desktop.

## Verified in source and automated checks

- Account registration and sign-in; case-insensitive unique usernames per host; display names can be reused; password hashes use PBKDF2-HMAC-SHA256.
- Device pairing requires an account session and pairing code. The host stores its vault phrase, pairing code, certificate, and database under the persistent server data directory. The smoke test restarts the host with the same data directory and verifies that the vault phrase and pairing code do not change.
- Saved-host list in the shared sidebar; reconnecting requires account sign-in, pairing code, and vault phrase. The saved address itself can become stale when the network changes; credentials do not provide address discovery or guarantee public inbound connectivity.
- Multiple servers, invites, server rename/delete, channel create/rename/delete, private-channel membership, owner/admin role controls, direct messages, message edit/delete, replies, reactions, pins, typing indicator, search, file/photo attachments, and recorded voice messages are present in the shared web client/server.
- One-to-one voice/video calls use WebRTC signaling. Screen share is attempted only where the browser/device API supports it; the client reports unsupported media capabilities.
- Host Manager is `server/settings_app.py`. It provides feature toggles for photos, voice messages, voice calls, video calls, and screen sharing, a Start server button, persistent configuration, and a RAM planning bar. The RAM value is an estimate, not a measured value or a hard cap.
- Windows notifications use the desktop Notification API when permission is granted. Android has a native notification bridge and notification channel. These are not a guarantee of push delivery when the client is suspended or terminated.
- Both Android and Windows render the shared `server/web/` UI, so sidebar and channel-management improvements belong in that shared client.

## CI evidence

Workflow run: https://github.com/dollax26-official/terminus-secret-chatting/actions/runs/39803349445

All four jobs passed on the audited main commit:
- Server protocol smoke tests and Python compilation, including the host settings manager.
- Windows Electron/shared-client syntax checks.
- Windows portable EXE build and artifact verification.
- Android APK build and artifact verification.

The smoke test exercises duplicate username rejection, reusable display names, pairing, encrypted message round-trips, server/channel management, private-channel access, role changes, DMs, encrypted call signaling, ciphertext-at-rest checks, and credential persistence after host restart.

## Known gaps / not yet proven production-ready

- There is no measured RAM cap. The settings app's model is a planning estimate; actual use depends on client count, active media, browser/WebView/Electron overhead, and operating-system background use.
- Automated source/protocol tests are not a substitute for a visual/responsive UI test suite at narrow Android widths, desktop widths, and real device permissions. No physical-device call test is represented by the CI run above.
- WebRTC currently uses a public STUN server and does not configure a TURN relay. Some NATs, mobile carriers, firewalls, or filtered networks can prevent calls even though signaling works. Screen capture is platform/browser dependent.
- Background push delivery is not implemented as a Web Push subscription flow. Notifications can be missed while the client is suspended or closed; Android native notifications also depend on the app's runtime lifecycle.
- The current DM/call flow is one-to-one. Group DMs and multiparty voice/video rooms are not established by the current smoke tests.
- Changing networks can change the public IPv6 address or make inbound IPv6 unavailable. Stable local credentials do not solve discovery, carrier filtering, firewall rules, or reachability. A stable hostname/dynamic DNS or another reachable rendezvous mechanism is needed for automatic reconnection across address changes.
- Media is not end-to-end encrypted by this app's vault scheme. WebRTC media transport security is provided by the WebRTC stack, but this project does not claim custom end-to-end media encryption.

## UI review basis

The shared web UI was checked against the targeted-review approach in [UI Guides & Agent Rules](https://github.com/strongeron/ui-guides-agent-rules): labeled form controls, recoverable inline errors, semantic buttons, keyboard focus, responsive sidebar/dialog behavior, explicit destructive-action confirmation, media capability feedback, and conservative memory use. The repository's `AGENTS.md` and `docs/ui-quality-checklist.md` preserve the ongoing review requirements.

## Local run commands (Windows)

From the repository root:

```powershell
py -m pip install -r server\requirements.txt
py server\settings_app.py
```

Configure capabilities and click **Start server** in the Host Manager. Keep the generated `server/data/` directory intact to preserve host credentials. Do not publish the vault phrase or master key.
