# Remote access

The host listens on `0.0.0.0:8443` by default. That makes it reachable on the local network, but a home router still blocks inbound connections from the internet. Pick one of the options below.

## Option 1 — Tailscale (recommended)

Tailscale puts every device on a private WireGuard network. It works through NAT, gives stable IPs, and encrypts traffic before it reaches the host.

1. Install Tailscale on the laptop, phone, and any other device.
2. Sign in to the same tailnet.
3. Start the host:

   ```powershell
   python server/host.py --port 8443
   ```

4. Find the laptop's Tailscale address:

   ```powershell
   tailscale ip -4
   ```

5. In the client use `https://<tailscale-ip>:8443` (or the MagicDNS name `https://laptop.<tailnet>.ts.net:8443`).

The certificate is self-signed and its SAN list does not include the Tailscale name. That is fine:

- **Windows** verifies the pinned certificate hash in the loopback proxy.
- **Android** handles the SSL error by comparing the certificate hash to the saved pin.
- **Chrome/PWA** shows a warning the first time; choose **Advanced → Proceed**.

No port forwarding, no public exposure.

## Option 2 — Cloudflare Tunnel

Use this when you cannot install Tailscale on the client, or want a normal public HTTPS hostname.

```powershell
cloudflared tunnel --url https://localhost:8443 --no-tls-verify
```

Cloudflare prints a URL such as `https://random-words.trycloudflare.com`. Enter that URL in the client.

Important: the certificate the client sees is **Cloudflare's edge certificate**, not the host's self-signed certificate. Trust the fingerprint shown on the first connection; it identifies the Cloudflare edge for that hostname. Cloudflare terminates TLS and forwards to your laptop; the tunnel connection to `localhost` uses `--no-tls-verify` because the origin is self-signed.

For a permanent hostname, create a named tunnel in the Cloudflare dashboard and point its service at `https://localhost:8443` with **No TLS Verify** enabled.

## Option 3 — LAN only

If all devices are on the same Wi-Fi:

```text
https://192.168.1.42:8443
```

This is the default printed by the host. It is the simplest setup and never leaves your network.

## Option 4 — Router port forwarding (not recommended)

Forward external TCP 8443 to the laptop's LAN IP. This exposes the host to the internet.

If you do this:

- Use a long, unique vault passphrase.
- Keep the host and Python dependencies updated.
- Watch the console for repeated pairing attempts (rate-limited to 8 per minute per IP).
- Prefer a firewall allowlist for the networks you actually use.
- Remember that the pairing code is printed in the console; do not screen-share it.

## Changing networks and IPs

The device token is independent of the client's IP. Moving from Wi-Fi to cellular, or from home to a coffee shop, does not log you out. Only reachability changes:

- On LAN, use the LAN URL.
- On Tailscale, use the Tailscale URL.
- Through a tunnel, use the tunnel URL.

If the host's address changes, open **Host & devices → Change host** on Windows (or clear app data on Android) and trust the host again.

## Certificate rotation

Deleting `server/data/cert.pem` and `key.pem` creates a new identity on the next start. Every client will reject the old pin:

- **Windows:** the app opens the setup screen automatically; re-trust the new fingerprint.
- **Android:** clear the app's storage (Android Settings → Apps → Terminus Secrets → Storage → Clear), then re-enter the address and trust the new fingerprint.
- **Browser/PWA:** clear site data for the host, or use a new browser profile.

Rotate the certificate if you suspect the key was copied.
