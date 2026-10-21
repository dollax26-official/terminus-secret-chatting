#!/usr/bin/env python3
"""
Terminus Secrets - Windows desktop client
=========================================

A native window (Edge WebView2 through pywebview) pointed at a loopback-only
proxy.  The proxy is the only component that talks to the host, and it refuses
to continue unless the host's certificate matches the fingerprint you approved.

Why a proxy?  Browsers refuse self-signed certificates.  Instead of disabling
checks globally, this app pins the exact certificate it saw during setup and
verifies every TLS connection against that pin.

Run from source:   python app.py
Build an .exe:     powershell -ExecutionPolicy Bypass -File build-exe.ps1
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

APP_NAME = "Terminus Secrets"
APP_VERSION = "1.0.0"
PROXY_PORT = 8756
MAX_PROXY_BODY = 2 * 1024 * 1024
CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "TerminusSecrets"
CONFIG_PATH = CONFIG_DIR / "config.json"
LOG_PATH = CONFIG_DIR / "app.log"

CONFIG: dict = {}
SERVER: ThreadingHTTPServer | None = None
PROXY_PORT_ACTUAL = 0


# --------------------------------------------------------------------------- #
# logging / config
# --------------------------------------------------------------------------- #
def log(message: str) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}  {message}\n")
    except OSError:
        pass


def load_config() -> dict:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def save_config(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=CONFIG_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        os.replace(tmp, CONFIG_PATH)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def normalize_fingerprint(value: str) -> str:
    return "".join(ch for ch in (value or "").lower() if ch in "0123456789abcdef")


def pretty_fingerprint(value: str) -> str:
    raw = normalize_fingerprint(value).upper()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


# --------------------------------------------------------------------------- #
# TLS pinning
# --------------------------------------------------------------------------- #
class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that trusts exactly one certificate fingerprint."""

    def __init__(self, host: str, port: int, pin: str, timeout: float = 60.0):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port=port, timeout=timeout, context=context)
        self.pin = normalize_fingerprint(pin)

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(der or b"").hexdigest()
        if not self.pin or not hmac.compare_digest(actual, self.pin):
            self.close()
            raise ssl.SSLError(
                "certificate pin mismatch: the host identity changed; reconnect through setup"
            )
        self.sock.settimeout(60.0)


def split_server_url(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("The host URL must start with https://")
    if not parsed.hostname:
        raise ValueError("The host URL is missing a hostname.")
    port = parsed.port or 443
    return parsed.hostname, port, parsed.path.rstrip("/")


def probe_host(url: str) -> dict:
    """Fetch /api/health without trusting anything yet, and report the cert pin."""
    host, port, _ = split_server_url(url)
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, port, timeout=12, context=context)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(der or b"").hexdigest()
        conn.request("GET", "/api/health", headers={"Accept": "application/json"})
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise ValueError(f"host answered HTTP {response.status}")
        health = json.loads(body.decode("utf-8"))
        if health.get("app") != "terminus-secrets":
            raise ValueError("that address is not a Terminus Secrets host")
        return {
            "ok": True,
            "url": url.rstrip("/"),
            "host": host,
            "port": port,
            "fingerprint": fingerprint,
            "server_name": health.get("server_name") or host,
            "version": health.get("version") or "?",
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# setup page
# --------------------------------------------------------------------------- #
SETUP_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Terminus Secrets â€” connect</title>
<style>
  :root{--bg:#06090e;--panel:#0c121a;--line:#1c2735;--text:#e8eef7;--muted:#8395aa;
        --faint:#5a6b7f;--accent:#3ee0c5;--danger:#ff7185;--mono:ui-monospace,"Cascadia Code",Consolas,monospace}
  *{box-sizing:border-box}
  html,body{height:100%;margin:0}
  body{background:
      radial-gradient(800px 520px at 12% -10%,rgba(62,224,197,.12),transparent 60%),
      radial-gradient(700px 480px at 95% 0%,rgba(111,157,255,.09),transparent 60%),
      var(--bg);
    color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;display:grid;place-items:center;overflow:auto}
  .wrap{width:min(720px,calc(100vw - 48px));padding:48px 0}
  .brand{display:flex;align-items:center;gap:12px;margin-bottom:34px}
  .mark{width:38px;height:38px;color:var(--accent)}
  .brand b{display:block;font-size:13px;letter-spacing:.3em}
  .brand small{display:block;font-family:var(--mono);font-size:9px;letter-spacing:.4em;color:var(--accent);margin-top:4px}
  h1{margin:0 0 12px;font-size:40px;line-height:1.08;letter-spacing:-.035em;font-weight:620;max-width:15ch}
  .lede{margin:0 0 30px;color:var(--muted);max-width:52ch;font-size:14.5px;line-height:1.6}
  .card{border:1px solid var(--line);border-radius:16px;background:rgba(12,18,26,.86);padding:24px;
        box-shadow:0 24px 70px rgba(0,0,0,.4)}
  label{display:block;font-family:var(--mono);font-size:10px;letter-spacing:.14em;
        text-transform:uppercase;color:var(--muted);margin-bottom:7px}
  input{width:100%;height:48px;padding:0 14px;border:1px solid var(--line);border-radius:11px;
        background:#080e15;color:var(--text);font:14px var(--mono);outline:none}
  input:focus{border-color:rgba(62,224,197,.4);box-shadow:0 0 0 4px rgba(62,224,197,.08)}
  .row{display:flex;gap:10px;margin-top:14px}
  button{height:44px;padding:0 20px;border-radius:10px;border:1px solid var(--line);
         background:transparent;color:var(--text);font-size:13.5px;cursor:pointer}
  button:hover{border-color:#2b3b4e}
  button.primary{background:linear-gradient(135deg,#4bf0d4,#2cc9b2);border:0;color:#04211d;font-weight:700;
                 box-shadow:0 10px 30px rgba(62,224,197,.18)}
  button.primary:disabled{opacity:.55;cursor:progress;box-shadow:none}
  .status{margin-top:16px;font-size:12.5px;color:var(--faint);min-height:18px;line-height:1.5}
  .status.error{color:var(--danger)}
  .result{display:none;margin-top:18px;padding-top:18px;border-top:1px solid #151f2b}
  .result.show{display:block}
  .server{font-size:15px;font-weight:600;margin:0 0 3px}
  .version{font-family:var(--mono);font-size:10px;color:var(--faint);margin:0 0 14px}
  .fplabel{font-family:var(--mono);font-size:9px;letter-spacing:.16em;color:var(--faint);text-transform:uppercase}
  .fp{font-family:var(--mono);font-size:10.5px;line-height:1.7;color:var(--accent);
      word-break:break-all;margin:5px 0 4px;user-select:text}
  .note{font-size:11px;color:var(--faint);line-height:1.55;margin:8px 0 0}
  .current{display:flex;align-items:center;gap:10px;padding:12px 14px;border:1px solid rgba(62,224,197,.2);
           background:rgba(62,224,197,.05);border-radius:10px;margin-bottom:18px;font-size:12.5px;color:var(--muted)}
  .current .dot{width:6px;height:6px;border-radius:50%;background:var(--accent)}
  .current b{color:var(--text);font-weight:600}
  .current .spacer{flex:1}
  .link{border:0;background:none;color:var(--faint);font-size:11.5px;padding:0;text-decoration:underline;height:auto}
  .link:hover{color:var(--accent)}
  .foot{margin-top:22px;display:flex;gap:18px;flex-wrap:wrap;font-family:var(--mono);font-size:9.5px;color:#4d5d70}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <svg class="mark" viewBox="0 0 48 48" fill="none"><path d="M24 4 43 24 24 44 5 24Z" stroke="currentColor" stroke-width="2.2"/><circle cx="24" cy="21" r="4.4" stroke="currentColor" stroke-width="2.2"/><path d="M24 25.5V33" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
    <div><b>TERMINUS</b><small>SECRETS</small></div>
  </div>

  <h1>Connect this desk to your host.</h1>
  <p class="lede">Enter the address of the laptop running <span style="font-family:var(--mono);font-size:12.5px">host.py</span>.
     The app will show you the host certificate fingerprint and remember only that exact identity.</p>

  <div class="card">
    <div class="current" id="current" style="display:none">
      <span class="dot"></span>
      <span>Paired with <b id="currentName">â€”</b></span>
      <span class="spacer"></span>
      <button type="button" class="link" id="changeBtn">change host</button>
    </div>

    <label for="url">Host address</label>
    <input id="url" spellcheck="false" value="https://127.0.0.1:8443" autocomplete="off">
    <div class="row">
      <button type="button" id="probeBtn">Test connection</button>
      <button type="button" class="primary" id="trustBtn" disabled>Trust &amp; open</button>
    </div>
    <div class="status" id="status" role="status"></div>

    <div class="result" id="result">
      <p class="server" id="serverName">â€”</p>
      <p class="version" id="serverVersion">â€”</p>
      <div class="fplabel">Certificate SHA-256 Â· verify against the host console</div>
      <div class="fp" id="fingerprint">â€”</div>
      <p class="note">Compare this with the fingerprint printed by the host on your laptop.
         If it differs, stop: you may be talking to the wrong machine.</p>
    </div>
  </div>

  <div class="foot">
    <span>â—ˆ LOOPBACK-ONLY PROXY</span><span>â—ˆ CERTIFICATE PINNING</span><span>â—ˆ AES-256-GCM VAULT</span>
  </div>
</div>

<script>
  const $ = (id) => document.getElementById(id);
  let probed = null;

  async function state() {
    try {
      const res = await fetch('/__state');
      const data = await res.json();
      if (data.configured) {
        $('url').value = data.server_url;
        $('current').style.display = 'flex';
        $('currentName').textContent = data.server_name || data.server_url;
        $('trustBtn').textContent = 'Open channel';
        $('trustBtn').disabled = false;
        probed = { url: data.server_url, fingerprint: data.fingerprint, server_name: data.server_name };
      }
    } catch (err) { /* first run */ }
  }

  async function probe() {
    const url = $('url').value.trim();
    $('status').className = 'status';
    $('status').textContent = 'Contacting hostâ€¦';
    $('result').classList.remove('show');
    $('trustBtn').disabled = true;
    probed = null;
    try {
      const res = await fetch('/__probe?url=' + encodeURIComponent(url));
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Could not reach that host.');
      probed = data;
      $('serverName').textContent = data.server_name;
      $('serverVersion').textContent = `Terminus Secrets host v${data.version} Â· ${data.host}:${data.port}`;
      $('fingerprint').textContent = data.fingerprint.replace(/(..)(?=.)/g, '$1:').toUpperCase();
      $('result').classList.add('show');
      $('status').textContent = 'Host reached. Compare the fingerprint, then trust it.';
      $('trustBtn').disabled = false;
      $('trustBtn').textContent = 'Trust & open';
    } catch (err) {
      $('status').className = 'status error';
      $('status').textContent = err.message || 'Could not reach that host.';
    }
  }

  async function trust() {
    if (!probed) return;
    $('trustBtn').disabled = true;
    $('status').className = 'status';
    $('status').textContent = 'Saving pinâ€¦';
    try {
      const res = await fetch('/__trust', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: probed.url, fingerprint: probed.fingerprint, server_name: probed.server_name})
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Could not save the host.');
      localStorage.removeItem('ts.token');
      localStorage.removeItem('ts.device');
      location.href = '/app/';
    } catch (err) {
      $('status').className = 'status error';
      $('status').textContent = err.message;
      $('trustBtn').disabled = false;
    }
  }

  $('probeBtn').addEventListener('click', probe);
  $('trustBtn').addEventListener('click', trust);
  $('url').addEventListener('keydown', (e) => { if (e.key === 'Enter') probe(); });
  $('changeBtn').addEventListener('click', () => {
    $('current').style.display = 'none';
    $('trustBtn').textContent = 'Trust & open';
    $('url').focus();
  });
  state();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# proxy
# --------------------------------------------------------------------------- #
FORWARD_REQUEST_HEADERS = ("Authorization", "Content-Type", "Accept", "User-Agent")
FORWARD_RESPONSE_HEADERS = (
    "Content-Type",
    "Cache-Control",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Service-Worker-Allowed",
    "Location",
)


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "TerminusDesktop/" + APP_VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("TERMINUS_VERBOSE"):
            log(fmt % args)

    # -- helpers ----------------------------------------------------------- #
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return origin == f"http://127.0.0.1:{PROXY_PORT_ACTUAL}"

    # -- GET --------------------------------------------------------------- #
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in ("/setup", "/setup/"):
            self._html(SETUP_HTML)
            return
        if parsed.path == "/__state":
            configured = bool(CONFIG.get("server_url") and CONFIG.get("fingerprint"))
            self._json(
                200,
                {
                    "configured": configured,
                    "server_url": CONFIG.get("server_url", ""),
                    "server_name": CONFIG.get("server_name", ""),
                    "fingerprint": pretty_fingerprint(CONFIG.get("fingerprint", "")),
                },
            )
            return
        if parsed.path == "/__probe":
            target = (parse_qs(parsed.query).get("url") or [""])[0]
            try:
                info = probe_host(target)
                self._json(200, info)
            except Exception as exc:  # noqa: BLE001 - surface the reason to the UI
                self._json(200, {"ok": False, "error": str(exc)})
            return
        if parsed.path == "/":
            self.send_response(302)
            self.send_header("Location", "/setup" if not CONFIG.get("server_url") else "/app/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._proxy("GET")

    # -- POST -------------------------------------------------------------- #
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/__trust":
            if not self._origin_ok():
                self._json(403, {"ok": False, "error": "bad origin"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                url = str(body.get("url") or "").rstrip("/")
                claimed = normalize_fingerprint(str(body.get("fingerprint") or ""))
                # Never trust the page: re-probe and compare the live certificate.
                info = probe_host(url)
                if not hmac.compare_digest(normalize_fingerprint(info["fingerprint"]), claimed):
                    raise ValueError("the host certificate changed during setup")
                CONFIG.update(
                    {
                        "server_url": url,
                        "fingerprint": info["fingerprint"],
                        "server_name": info["server_name"],
                        "paired_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    }
                )
                save_config(CONFIG)
                log(f"trusted host {url} pin={info['fingerprint'][:16]}â€¦")
                self._json(200, {"ok": True})
            except Exception as exc:  # noqa: BLE001
                self._json(200, {"ok": False, "error": str(exc)})
            return
        self._proxy("POST")

    # -- proxy core -------------------------------------------------------- #
    def _proxy(self, method: str) -> None:
        if not CONFIG.get("server_url") or not CONFIG.get("fingerprint"):
            self.send_response(302)
            self.send_header("Location", "/setup")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        parsed = urlparse(self.path)
        if not (parsed.path == "/app" or parsed.path.startswith("/app/") or parsed.path.startswith("/api/")):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_PROXY_BODY:
            self._json(413, {"error": "body too large"})
            return
        body = self.rfile.read(length) if length else None

        headers = {}
        for name in FORWARD_REQUEST_HEADERS:
            value = self.headers.get(name)
            if value:
                headers[name] = value
        headers["Accept-Encoding"] = "identity"

        try:
            host, port, _ = split_server_url(CONFIG["server_url"])
            conn = PinnedHTTPSConnection(host, port, CONFIG["fingerprint"], timeout=60)
            try:
                conn.request(method, self.path, body=body, headers=headers)
                response = conn.getresponse()
                payload = response.read()
                self.send_response(response.status)
                for name in FORWARD_RESPONSE_HEADERS:
                    value = response.getheader(name)
                    if value:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                conn.close()
        except ssl.SSLError as exc:
            log(f"TLS pin failure: {exc}")
            self._json(502, {"error": "host identity check failed; re-run setup"})
        except Exception as exc:  # noqa: BLE001
            log(f"proxy error: {exc}")
            try:
                self._json(502, {"error": f"host unreachable: {exc}"})
            except (BrokenPipeError, ConnectionResetError):
                pass


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_proxy(port: int = PROXY_PORT) -> tuple[ProxyServer, int]:
    server = ProxyServer(("127.0.0.1", port), ProxyHandler)
    global PROXY_PORT_ACTUAL
    PROXY_PORT_ACTUAL = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
    thread.start()
    return server, PROXY_PORT_ACTUAL


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def selftest() -> int:
    server, port = start_proxy(0)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/setup")
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        ok = response.status == 200 and "Terminus Secrets" in body
        log(f"selftest port={port} ok={ok}")
        print(f"selftest {'ok' if ok else 'FAILED'} on 127.0.0.1:{port}")
        return 0 if ok else 1
    finally:
        server.shutdown()
        server.server_close()


def show_error(message: str) -> None:
    log("FATAL " + message)
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, message, APP_NAME, 0x10)
    except Exception:  # noqa: BLE001
        print(message, file=sys.stderr)


def main() -> int:
    global CONFIG
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG = load_config()

    if "--selftest" in sys.argv:
        return selftest()

    force_setup = "--setup" in sys.argv
    try:
        server, port = start_proxy(PROXY_PORT)
    except OSError:
        show_error(
            "Terminus Secrets is already running (or port 8756 is busy).\n"
            "Close the other window and try again."
        )
        return 1

    if force_setup or not CONFIG.get("server_url"):
        start_url = f"http://127.0.0.1:{port}/setup"
    else:
        # Re-verify the pinned host before opening the chat, so an identity
        # change lands on the setup screen instead of a broken chat.
        try:
            info = probe_host(CONFIG["server_url"])
            if normalize_fingerprint(info["fingerprint"]) != normalize_fingerprint(
                CONFIG.get("fingerprint", "")
            ):
                raise ValueError("host certificate changed")
            start_url = f"http://127.0.0.1:{port}/app/"
        except Exception as exc:  # noqa: BLE001
            log(f"startup probe failed: {exc}")
            start_url = f"http://127.0.0.1:{port}/setup"

    try:
        import webview
    except ImportError as exc:
        show_error(f"pywebview is missing: {exc}\nRun: pip install -r requirements.txt")
        server.shutdown()
        return 1

    log(f"opening {start_url}")
    window = webview.create_window(
        APP_NAME,
        url=start_url,
        width=1220,
        height=800,
        min_size=(940, 600),
        background_color="#06090e",
        text_select=True,
    )
    try:
        webview.start(debug=False)
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

