# Remote access (different Wi-Fi / mobile data)

The host already binds to `0.0.0.0`, so it listens on the host computer's network interfaces. That alone does **not** make a home computer reachable from the public internet: the router and ISP must allow inbound connections.

## Option A — router port forwarding

1. Start `host.py` on the Windows computer and keep it running.
2. Give that computer a reserved/static **LAN** address in your router (for example, `192.168.1.50`).
3. In the router's Port Forwarding / NAT page, forward **TCP port 8443** from the internet to that computer's LAN address, port **8443**.
4. Allow inbound TCP 8443 in Windows Firewall (run PowerShell as Administrator):

   ```powershell
   New-NetFirewallRule -DisplayName "Terminus Secrets HTTPS" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8443 -Profile Private,Public
   ```

5. Find your public IPv4 address, or configure a Dynamic DNS hostname if it changes.
6. Start the host with the address clients should use:

   ```powershell
   python host.py --host 0.0.0.0 --port 8443 --public-url https://YOUR-PUBLIC-IP:8443
   ```

   Replace the example with your real public IP or hostname. On each remote Android device, enter `https://YOUR-PUBLIC-IP:8443` in the app. Compare the certificate SHA-256 fingerprint shown in the app with the fingerprint printed by the host before trusting it.

**Do not expose this host without sharing the pairing code and vault passphrase only with people you trust.** The host stores message ciphertext locally; anyone who has the vault passphrase and database can decrypt the history.

## If port forwarding does not work

Some ISPs use CGNAT or block inbound ports. In that case, router port forwarding cannot make the host reachable. You need a secure outbound tunnel or a public relay/VPS. A normal HTTPS tunnel terminates TLS at the tunnel provider, so this app's certificate-pin flow must be adapted for that tunnel before using it; do not simply disable certificate checks.

## Quick checks

- From the host computer, open `https://127.0.0.1:8443/api/health` (a browser warning is expected for the self-signed certificate).
- From the same Wi-Fi, test `https://LAN-IP:8443/api/health`.
- From mobile data or a different network, test `https://PUBLIC-IP-OR-HOSTNAME:8443/api/health`.
- If the first two work but the last fails, check port forwarding, Windows Firewall, the public IP, and whether the ISP uses CGNAT.
- Keep TCP 8443 forwarded only while you intend to host the chat.
