#!/usr/bin/env python3
"""
Terminus Secrets - host server
==============================

Runs on the owner's laptop. It is deliberately "dumb":

  * it authenticates paired devices with long-lived random tokens,
  * it stores and relays *ciphertext* only,
  * it keeps every message in a SQLite database on this machine.

The vault key never reaches this process. Clients derive it from a passphrase
(PBKDF2-HMAC-SHA256, 600k iterations) and encrypt with AES-256-GCM.

Usage:
    python host.py                 # https://0.0.0.0:8443
    python host.py --port 9443
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import socket
import sqlite3
import ssl
import string
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

APP_NAME = "Terminus Secrets"
APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
DEFAULT_DATA_DIR = BASE_DIR / "data"

MAX_BODY = 128 * 1024
MAX_CIPHERTEXT = 96 * 1024
KDF_ITERATIONS = 600_000
PAIR_ATTEMPTS_PER_MINUTE = 8

# Filled in by main()
DATA_DIR: Path = DEFAULT_DATA_DIR
DB_PATH: Path = DEFAULT_DATA_DIR / "terminus.db"
PAIR_CODE = ""
MASTER_KEY = ""
CERT_FINGERPRINT = ""
SERVER_NAME = socket.gethostname()
LAN_IP = "127.0.0.1"
PUBLIC_URL = ""
MESSAGE_COND = threading.Condition()
PAIR_LOCK = threading.Lock()
PAIR_ATTEMPTS: dict[str, list[float]] = {}
LAST_SEEN_CACHE: dict[str, float] = {}

MIME_OVERRIDES = {
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_meta(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def make_passphrase() -> str:
    alphabet = string.ascii_lowercase
    return "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4))


# --------------------------------------------------------------------------- #
# certificates
# --------------------------------------------------------------------------- #
def ensure_certificate(cert_path: Path, key_path: Path) -> None:
    if cert_path.exists() and key_path.exists():
        return

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Terminus Secrets Host"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Terminus Secrets"),
        ]
    )
    san = [
        x509.DNSName("localhost"),
        x509.DNSName(socket.gethostname()),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    try:
        san.append(x509.IPAddress(ipaddress.ip_address(LAN_IP)))
    except ValueError:
        pass

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(microsecond=0))
        .not_valid_after(now.replace(year=now.year + 10, microsecond=0))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    if os.name == "nt":
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass


def cert_fingerprint(cert_path: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


# --------------------------------------------------------------------------- #
# database
# --------------------------------------------------------------------------- #
def init_db(passphrase: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_seen TEXT,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL REFERENCES rooms(id),
                device_id TEXT NOT NULL REFERENCES devices(id),
                client_msg_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(device_id, client_msg_id)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);
            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, id);
            """
        )
        if not conn.execute("SELECT 1 FROM rooms WHERE id='general'").fetchone():
            conn.execute(
                "INSERT INTO rooms(id, name, created_at) VALUES('general','general',?)",
                (now_iso(),),
            )
        room_columns = [row["name"] for row in conn.execute("PRAGMA table_info(rooms)")]
        if "description" not in room_columns:
            conn.execute("ALTER TABLE rooms ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        if not conn.execute("SELECT 1 FROM meta WHERE key='vault_salt'").fetchone():
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('vault_salt', ?)",
                (b64e(secrets.token_bytes(16)),),
            )
        if not conn.execute("SELECT 1 FROM meta WHERE key='kdf_iterations'").fetchone():
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('kdf_iterations', ?)",
                (str(KDF_ITERATIONS),),
            )

    pass_file = DATA_DIR / "vault-passphrase.txt"
    if not pass_file.exists():
        pass_file.write_text(passphrase + "\n", encoding="utf-8")


def ensure_master_key(rotate: bool = False) -> str:
    """Long-lived enrollment secret, separate from the vault passphrase."""
    global MASTER_KEY
    path = DATA_DIR / "master-key.txt"
    if rotate or not path.exists():
        MASTER_KEY = secrets.token_urlsafe(32)
        path.write_text(MASTER_KEY + "\n", encoding="utf-8")
    else:
        MASTER_KEY = path.read_text(encoding="utf-8").strip()
        if not MASTER_KEY:
            MASTER_KEY = secrets.token_urlsafe(32)
            path.write_text(MASTER_KEY + "\n", encoding="utf-8")
    set_meta("master_key_hash", sha256_hex(MASTER_KEY))
    return MASTER_KEY


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "TerminusSecrets/" + APP_VERSION
    protocol_version = "HTTP/1.1"

    # -- low level --------------------------------------------------------- #
    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        if os.environ.get("TERMINUS_VERBOSE"):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _common_headers(self, ctype: str, length: int, cache: str = "no-store") -> None:
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )

    def _send_json(self, status: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(status)
            self._common_headers("application/json; charset=utf-8", len(data))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_bytes(
        self, status: int, data: bytes, ctype: str, extra: dict[str, str] | None = None
    ) -> None:
        try:
            self.send_response(status)
            self._common_headers(ctype, len(data))
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    # -- auth -------------------------------------------------------------- #
    def _device(self) -> sqlite3.Row | None:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[7:].strip()
        if not token.startswith("ts_") or len(token) < 20:
            return None
        token_hash = sha256_hex(token)
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE token_hash=? AND revoked=0", (token_hash,)
            ).fetchone()
            if row is None:
                return None
            last = LAST_SEEN_CACHE.get(row["id"], 0)
            if time.time() - last > 30:
                conn.execute(
                    "UPDATE devices SET last_seen=? WHERE id=?", (now_iso(), row["id"])
                )
                LAST_SEEN_CACHE[row["id"]] = time.time()
        return row

    def _require_device(self) -> sqlite3.Row | None:
        device = self._device()
        if device is None:
            self._error(401, "unauthorized")
        return device

    # -- GET --------------------------------------------------------------- #
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/app/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/api/health":
            self._send_json(
                200,
                {
                    "app": "terminus-secrets",
                    "version": APP_VERSION,
                    "server_name": SERVER_NAME,
                    "fingerprint": CERT_FINGERPRINT,
                    "tls": True,
                    "time": now_iso(),
                },
            )
            return

        if path == "/api/vault":
            if self._require_device() is None:
                return
            check_nonce = get_meta("vault_check_nonce")
            check_ct = get_meta("vault_check_ct")
            self._send_json(
                200,
                {
                    "salt": get_meta("vault_salt"),
                    "iterations": int(get_meta("kdf_iterations", str(KDF_ITERATIONS))),
                    "alg": "AES-256-GCM",
                    "kdf": "PBKDF2-HMAC-SHA256",
                    "check": (
                        {"nonce": check_nonce, "ciphertext": check_ct}
                        if check_nonce and check_ct
                        else None
                    ),
                },
            )
            return

        if path == "/api/sync":
            device = self._require_device()
            if device is None:
                return
            try:
                after = int((query.get("after") or ["0"])[0])
            except ValueError:
                after = 0
            try:
                wait = min(max(int((query.get("wait") or ["0"])[0]), 0), 25)
            except ValueError:
                wait = 0
            self._sync(device, max(after, 0), wait)
            return

        if path.startswith("/api/"):
            self._error(404, "not found")
            return

        if path == "/app" or path.startswith("/app/"):
            rel = path[len("/app/") :] if path.startswith("/app/") else ""
            self._serve_static(rel or "index.html")
            return

        self._error(404, "not found")

    def _sync(self, device: sqlite3.Row, after: int, wait: int) -> None:
        deadline = time.time() + wait
        while True:
            with db() as conn:
                rows = conn.execute(
                    """
                    SELECT m.id, m.room_id, m.device_id, m.client_msg_id,
                           m.nonce, m.ciphertext, m.created_at, d.name AS device_name
                    FROM messages m JOIN devices d ON d.id = m.device_id
                    WHERE m.id > ? ORDER BY m.id ASC LIMIT 200
                    """,
                    (after,),
                ).fetchall()
                if rows or time.time() >= deadline or wait == 0:
                    rooms = conn.execute(
                        "SELECT id, name, description, created_at FROM rooms ORDER BY created_at ASC"
                    ).fetchall()
                    devices = conn.execute(
                        "SELECT id, name, created_at, last_seen FROM devices "
                        "WHERE revoked=0 ORDER BY created_at ASC"
                    ).fetchall()
                    more = conn.execute(
                        "SELECT 1 FROM messages WHERE id > ? LIMIT 1",
                        (rows[-1]["id"] if rows else after,),
                    ).fetchone()
                    payload = {
                        "messages": [
                            {
                                "id": r["id"],
                                "room_id": r["room_id"],
                                "device_id": r["device_id"],
                                "device_name": r["device_name"],
                                "client_msg_id": r["client_msg_id"],
                                "nonce": b64e(r["nonce"]),
                                "ciphertext": b64e(r["ciphertext"]),
                                "created_at": r["created_at"],
                            }
                            for r in rows
                        ],
                        "rooms": [
                            {
                                "id": r["id"],
                                "name": r["name"],
                                "description": r["description"],
                                "created_at": r["created_at"],
                            }
                            for r in rooms
                        ],
                        "devices": [
                            {
                                "id": r["id"],
                                "name": r["name"],
                                "created_at": r["created_at"],
                                "last_seen": r["last_seen"],
                            }
                            for r in devices
                        ],
                        "you": device["id"],
                        "last_id": rows[-1]["id"] if rows else after,
                        "has_more": bool(more),
                        "server_time": now_iso(),
                        "vault": {
                            "salt": get_meta("vault_salt"),
                            "iterations": int(
                                get_meta("kdf_iterations", str(KDF_ITERATIONS))
                            ),
                        },
                    }
                    self._send_json(200, payload)
                    return
            with MESSAGE_COND:
                remaining = deadline - time.time()
                if remaining <= 0:
                    continue
                MESSAGE_COND.wait(timeout=min(remaining, 20.0))

    def _serve_static(self, rel: str) -> None:
        base = WEB_DIR.resolve()
        candidate = (base / rel).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            self._error(404, "not found")
            return
        if candidate.is_dir():
            candidate = candidate / "index.html"
        if not candidate.is_file():
            self._error(404, "not found")
            return
        ext = candidate.suffix.lower()
        ctype = MIME_OVERRIDES.get(ext) or mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        data = candidate.read_bytes()
        headers: dict[str, str] = {}
        if rel.endswith("sw.js"):
            headers["Service-Worker-Allowed"] = "/app/"
        if ext == ".html":
            headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                "worker-src 'self'"
            )
        self._send_bytes(200, data, ctype, headers)

    # -- POST -------------------------------------------------------------- #
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            body = self._read_json()
        except (ValueError, json.JSONDecodeError):
            self._error(400, "invalid json")
            return

        if path == "/api/pair":
            self._pair(body)
            return

        if path == "/api/vault/check":
            if self._require_device() is None:
                return
            try:
                nonce = b64d(str(body.get("nonce") or ""))
                ciphertext = b64d(str(body.get("ciphertext") or ""))
            except (ValueError, TypeError):
                self._error(400, "invalid check blob")
                return
            if len(nonce) != 12 or not ciphertext or len(ciphertext) > 4096:
                self._error(400, "invalid check blob")
                return
            with db() as conn:
                existing = conn.execute(
                    "SELECT value FROM meta WHERE key='vault_check_ct'"
                ).fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO meta(key, value) VALUES('vault_check_nonce', ?), "
                        "('vault_check_ct', ?)",
                        (b64e(nonce), b64e(ciphertext)),
                    )
            self._send_json(200, {"ok": True, "created": existing is None})
            return

        if path == "/api/messages":
            device = self._require_device()
            if device is None:
                return
            self._post_message(device, body)
            return

        if path == "/api/rooms":
            device = self._require_device()
            if device is None:
                return
            self._create_room(device, body)
            return

        if path == "/api/devices/revoke":
            device = self._require_device()
            if device is None:
                return
            target = str(body.get("device_id") or "")
            if not target:
                self._error(400, "device_id required")
                return
            with db() as conn:
                conn.execute("UPDATE devices SET revoked=1 WHERE id=?", (target,))
            self._send_json(200, {"ok": True, "revoked": target})
            return

        self._error(404, "not found")

    def _pair(self, body: dict) -> None:
        ip = self.client_address[0]
        with PAIR_LOCK:
            now = time.time()
            attempts = [t for t in PAIR_ATTEMPTS.get(ip, []) if now - t < 60]
            if len(attempts) >= PAIR_ATTEMPTS_PER_MINUTE:
                self._error(429, "too many attempts, wait a minute")
                return
            attempts.append(now)
            PAIR_ATTEMPTS[ip] = attempts

        master_key = str(body.get("master_key") or "").strip()
        code = str(body.get("code") or "").strip().upper().replace(" ", "")
        name = " ".join(str(body.get("device_name") or "").split())[:40] or "Device"
        if master_key:
            if not hmac.compare_digest(master_key, MASTER_KEY):
                self._error(403, "invalid master key")
                return
        elif not hmac.compare_digest(code, PAIR_CODE):
            self._error(403, "invalid pairing code")
            return

        token = "ts_" + secrets.token_urlsafe(32)
        device_id = "dev_" + secrets.token_hex(6)
        with db() as conn:
            conn.execute(
                "INSERT INTO devices(id, name, token_hash, created_at, last_seen) "
                "VALUES(?,?,?,?,?)",
                (device_id, name, sha256_hex(token), now_iso(), now_iso()),
            )
        self._send_json(
            200,
            {
                "token": token,
                "device_id": device_id,
                "device_name": name,
                "server_name": SERVER_NAME,
                "fingerprint": CERT_FINGERPRINT,
            },
        )

    def _post_message(self, device: sqlite3.Row, body: dict) -> None:
        room_id = str(body.get("room_id") or "")
        client_msg_id = str(body.get("client_msg_id") or "")[:64]
        try:
            nonce = b64d(str(body.get("nonce") or ""))
            ciphertext = b64d(str(body.get("ciphertext") or ""))
        except (ValueError, TypeError):
            self._error(400, "invalid ciphertext")
            return

        if len(nonce) != 12:
            self._error(400, "nonce must be 12 bytes")
            return
        if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT:
            self._error(400, "ciphertext size invalid")
            return
        if not client_msg_id:
            self._error(400, "client_msg_id required")
            return

        with db() as conn:
            room = conn.execute("SELECT 1 FROM rooms WHERE id=?", (room_id,)).fetchone()
            if room is None:
                self._error(404, "room not found")
                return
            try:
                cur = conn.execute(
                    "INSERT INTO messages(room_id, device_id, client_msg_id, nonce, ciphertext, created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (room_id, device["id"], client_msg_id, nonce, ciphertext, now_iso()),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT id, created_at FROM messages WHERE device_id=? AND client_msg_id=?",
                    (device["id"], client_msg_id),
                ).fetchone()
                self._send_json(
                    200,
                    {
                        "id": row["id"],
                        "created_at": row["created_at"],
                        "duplicate": True,
                    },
                )
                return
            message_id = cur.lastrowid
            created_at = conn.execute(
                "SELECT created_at FROM messages WHERE id=?", (message_id,)
            ).fetchone()["created_at"]

        with MESSAGE_COND:
            MESSAGE_COND.notify_all()
        self._send_json(200, {"id": message_id, "created_at": created_at})

    def _create_room(self, device: sqlite3.Row, body: dict) -> None:
        name = " ".join(str(body.get("name") or "").split())[:32]
        description = " ".join(str(body.get("description") or "").split())[:120]
        if not name:
            self._error(400, "name required")
            return
        room_id = "r_" + secrets.token_hex(5)
        with db() as conn:
            conn.execute(
                "INSERT INTO rooms(id, name, description, created_at) VALUES(?,?,?,?)",
                (room_id, name, description, now_iso()),
            )
        with MESSAGE_COND:
            MESSAGE_COND.notify_all()
        self._send_json(
            200,
            {
                "id": room_id,
                "name": name,
                "description": description,
                "created_at": now_iso(),
            },
        )


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def print_banner(port: int, passphrase: str) -> None:
    lines = [
        "",
        "=" * 66,
        "  TERMINUS SECRETS  -  host online",
        "=" * 66,
        f"  This laptop :  https://127.0.0.1:{port}/app/",
        f"  Network     :  https://{LAN_IP}:{port}/app/",
        f"  Public URL  :  {PUBLIC_URL + '/app/' if PUBLIC_URL else 'not set (use LAN, Tailscale, or a tunnel)'}",
        f"  Pairing code:  {PAIR_CODE}",
        f"  Master key  :  {MASTER_KEY}",
        f"  Vault phrase:  {passphrase}",
        "",
        "  Master key = add a new device. Vault phrase = decrypt history.",
        "  All messages are stored encrypted in:",
        f"    {DB_PATH}",
        "",
        "  Keep this window open while you chat.",
        "  Ctrl+C stops the host (history stays on disk).",
        "=" * 66,
        "",
    ]
    text = "\n".join(lines)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    print(text, flush=True)

class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_V6ONLY,
            0,
        )
        super().server_bind()
def main() -> int:
    global DATA_DIR, DB_PATH, PAIR_CODE, MASTER_KEY, CERT_FINGERPRINT, LAN_IP, SERVER_NAME, PUBLIC_URL

    parser = argparse.ArgumentParser(description="Terminus Secrets host")
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443, help="HTTPS port (default 8443)")
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    parser.add_argument("--public-url", default=os.environ.get("TERMINUS_PUBLIC_URL", ""),
                        help="public HTTPS URL or IP clients use from outside this network")
    parser.add_argument("--rotate-master-key", action="store_true",
                        help="generate a new master key, print it, and exit")
    args = parser.parse_args()

    DATA_DIR = Path(args.data_dir).resolve()
    DB_PATH = DATA_DIR / "terminus.db"
    LAN_IP = local_ip()
    SERVER_NAME = socket.gethostname()
    PUBLIC_URL = args.public_url.strip().rstrip("/")
    if PUBLIC_URL and not PUBLIC_URL.startswith("https://"):
        parser.error("--public-url must start with https://")

    pass_file = DATA_DIR / "vault-passphrase.txt"
    passphrase = (
        pass_file.read_text(encoding="utf-8").strip()
        if pass_file.exists()
        else make_passphrase()
    )
    init_db(passphrase)

    if args.rotate_master_key:
        rotated = ensure_master_key(rotate=True)
        print("New master key: " + rotated)
        print("data/master-key.txt updated; existing devices stay paired.")
        return 0

    ensure_master_key()

    cert_path = DATA_DIR / "cert.pem"
    key_path = DATA_DIR / "key.pem"
    ensure_certificate(cert_path, key_path)
    CERT_FINGERPRINT = cert_fingerprint(cert_path)

    PAIR_CODE = secrets.token_hex(2).upper() + "-" + secrets.token_hex(2).upper()
    (DATA_DIR / "pairing-code.txt").write_text(PAIR_CODE + "\n", encoding="utf-8")

    IPv6ThreadingHTTPServer.allow_reuse_address = True
    httpd = IPv6ThreadingHTTPServer(("::", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print_banner(args.port, passphrase)
    try:
        httpd.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nShutting down. History is safe on disk.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
