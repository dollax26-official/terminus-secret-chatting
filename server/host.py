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
ROOM_ADMIN_KEY = ""  # Optional; when set, only key holders may create groups.
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
    # WAL is enabled once during database initialization, not on every request.
    # Re-running journal_mode=WAL for every short-lived connection adds avoidable
    # locking and filesystem work to the hot message/sync path.
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
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
        # Set the persistent journal mode once at startup.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS account_sessions (
                token_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                invite_code TEXT NOT NULL UNIQUE,
                owner_account_id TEXT REFERENCES accounts(id),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_members (
                server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at TEXT NOT NULL,
                PRIMARY KEY(server_id, account_id)
            );
            CREATE INDEX IF NOT EXISTS idx_account_sessions_expiry ON account_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_seen TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                account_id TEXT REFERENCES accounts(id)
            );
            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                server_id TEXT NOT NULL DEFAULT 'srv_default'
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL REFERENCES rooms(id),
                device_id TEXT NOT NULL REFERENCES devices(id),
                client_msg_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL,
                edited_at TEXT,
                deleted_at TEXT,
                pinned INTEGER NOT NULL DEFAULT 0,
                reply_to_id INTEGER,
                UNIQUE(device_id, client_msg_id)
            );
            CREATE TABLE IF NOT EXISTS reactions (
                message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                emoji TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(message_id, account_id, emoji)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);
            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, id);
            """
        )
        message_columns = [row["name"] for row in conn.execute("PRAGMA table_info(messages)")]
        for column, definition in (
            ("edited_at", "TEXT"),
            ("deleted_at", "TEXT"),
            ("pinned", "INTEGER NOT NULL DEFAULT 0"),
            ("reply_to_id", "INTEGER"),
        ):
            if column not in message_columns:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {column} {definition}")

        device_columns = [row["name"] for row in conn.execute("PRAGMA table_info(devices)")]
        if "account_id" not in device_columns:
            conn.execute("ALTER TABLE devices ADD COLUMN account_id TEXT REFERENCES accounts(id)")

        room_columns = [row["name"] for row in conn.execute("PRAGMA table_info(rooms)")]
        if "server_id" not in room_columns:
            conn.execute("ALTER TABLE rooms ADD COLUMN server_id TEXT NOT NULL DEFAULT 'srv_default'")
        if not conn.execute("SELECT 1 FROM servers LIMIT 1").fetchone():
            conn.execute(
                "INSERT INTO servers(id, name, description, invite_code, owner_account_id, created_at) VALUES(?,?,?,?,?,?)",
                ("srv_default", "My Server", "Default Terminus server", secrets.token_urlsafe(9), None, now_iso()),
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
    def _account_session_id(self) -> str | None:
        token = self.headers.get("X-Account-Token", "").strip()
        if len(token) < 32:
            return None
        with db() as conn:
            row = conn.execute(
                "SELECT account_id FROM account_sessions WHERE token_hash=? AND expires_at>?",
                (sha256_hex(token), int(time.time())),
            ).fetchone()
        return row["account_id"] if row else None

    def _device(self) -> sqlite3.Row | None:
        account_id = self._account_session_id()
        if account_id is None:
            return None
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[7:].strip()
        if not token.startswith("ts_") or len(token) < 20:
            return None
        token_hash = sha256_hex(token)
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE token_hash=? AND revoked=0 AND account_id=?",
                (token_hash, account_id),
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
            updated_after = (query.get("updated_after") or [""])[0][:40]
            server_id = (query.get("server_id") or [""])[0][:80]
            self._sync(device, max(after, 0), wait, updated_after, server_id)
            return

        if path.startswith("/api/"):
            self._error(404, "not found")
            return

        if path == "/app" or path.startswith("/app/"):
            rel = path[len("/app/") :] if path.startswith("/app/") else ""
            self._serve_static(rel or "index.html")
            return

        self._error(404, "not found")

    def _sync(self, device: sqlite3.Row, after: int, wait: int, updated_after: str = "", server_id: str = "") -> None:
        if not server_id:
            with db() as conn:
                membership = conn.execute(
                    "SELECT server_id FROM server_members WHERE account_id=? ORDER BY joined_at ASC LIMIT 1",
                    (device["account_id"],),
                ).fetchone()
            server_id = membership["server_id"] if membership else ""
        deadline = time.monotonic() + wait
        while True:
            # Hold the condition lock while checking SQLite. The previous
            # check-then-wait sequence could miss a notify between the SELECT
            # and Condition.wait(), leaving clients asleep for up to 20 seconds.
            # Condition.wait() releases the lock atomically, so a message commit
            # cannot slip into that gap.
            with MESSAGE_COND:
                with db() as conn:
                    rows = conn.execute(
                        """
                        SELECT m.id, m.room_id, m.device_id, m.client_msg_id,
                               m.nonce, m.ciphertext, m.created_at, m.edited_at,
                               m.deleted_at, m.pinned, m.reply_to_id,
                               COALESCE(a.username, d.name) AS device_name,
                               COALESCE((SELECT json_group_array(json_object('emoji', r.emoji, 'count', r.n))
                                         FROM (SELECT emoji, COUNT(*) AS n FROM reactions
                                               WHERE message_id=m.id GROUP BY emoji) r), '[]') AS reactions_json
                        FROM messages m JOIN devices d ON d.id = m.device_id
                        LEFT JOIN accounts a ON a.id = d.account_id
                        WHERE (m.id > ? OR (m.edited_at IS NOT NULL AND m.edited_at > ?)
                              OR (m.deleted_at IS NOT NULL AND m.deleted_at > ?))
                          AND m.room_id IN (
                              SELECT r.id FROM rooms r JOIN server_members sm ON sm.server_id=r.server_id
                              WHERE sm.account_id=? AND (?='' OR r.server_id=?)
                          )
                         ORDER BY m.id ASC LIMIT 200
                        """,
                        (after, updated_after, updated_after, device["account_id"], server_id, server_id),
                    ).fetchall()
                    remaining = deadline - time.monotonic()
                    if rows or remaining <= 0 or wait == 0:
                        rooms = conn.execute(
                            """SELECT r.id, r.name, r.description, r.created_at, r.server_id
                               FROM rooms r JOIN server_members sm ON sm.server_id=r.server_id
                               WHERE sm.account_id=? AND (?='' OR r.server_id=?)
                               ORDER BY r.created_at ASC""",
                            (device["account_id"], server_id, server_id),
                        ).fetchall()
                        servers = conn.execute(
                            """SELECT s.id, s.name, s.description, s.invite_code, sm.role
                               FROM servers s JOIN server_members sm ON sm.server_id=s.id
                               WHERE sm.account_id=? ORDER BY s.created_at ASC""",
                            (device["account_id"],),
                        ).fetchall()
                        devices = conn.execute(
                            "SELECT id, name, created_at, last_seen FROM devices "
                            "WHERE revoked=0 AND account_id=? ORDER BY created_at ASC",
                            (device["account_id"],),
                        ).fetchall()
                        cursor_id = max([after] + [row["id"] for row in rows])
                        more = conn.execute(
                            """SELECT 1 FROM messages m WHERE m.id > ? AND m.room_id IN (
                                   SELECT r.id FROM rooms r JOIN server_members sm ON sm.server_id=r.server_id
                                   WHERE sm.account_id=? AND r.server_id=?
                               ) LIMIT 1""",
                            (cursor_id, device["account_id"], server_id),
                        ).fetchone()
                        payload = {
                            "messages": [
                                {
                                    "id": row["id"],
                                    "room_id": row["room_id"],
                                    "device_id": row["device_id"],
                                    "device_name": row["device_name"],
                                    "client_msg_id": row["client_msg_id"],
                                    "nonce": b64e(row["nonce"]),
                                    "ciphertext": b64e(row["ciphertext"]),
                                    "created_at": row["created_at"],
                                    "edited_at": row["edited_at"],
                                    "deleted": bool(row["deleted_at"]),
                                    "pinned": bool(row["pinned"]),
                                    "reply_to_id": row["reply_to_id"],
                                    "reactions": json.loads(row["reactions_json"] or "[]"),
                                }
                                for row in rows
                            ],
                            "rooms": [
                                {
                                    "id": row["id"],
                                    "name": row["name"],
                                    "description": row["description"],
                                    "created_at": row["created_at"],
                                    "server_id": row["server_id"],
                                }
                                for row in rooms
                            ],
                            "servers": [dict(row) for row in servers],
                            "devices": [
                                {
                                    "id": row["id"],
                                    "name": row["name"],
                                    "created_at": row["created_at"],
                                    "last_seen": row["last_seen"],
                                }
                                for row in devices
                            ],
                            "you": device["id"],
                            "active_server_id": server_id,
                            "last_id": max([after] + [row["id"] for row in rows]),
                            "has_more": bool(more),
                            "server_time": now_iso(),
                            "room_admin_required": bool(ROOM_ADMIN_KEY),
                            "vault": {
                                "salt": get_meta("vault_salt"),
                                "iterations": int(get_meta("kdf_iterations", str(KDF_ITERATIONS))),
                            },
                        }
                        break
                MESSAGE_COND.wait(timeout=min(max(remaining, 0), 20.0))

        self._send_json(200, payload)

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

        if path == "/api/accounts/register":
            self._account_register(body)
            return

        if path == "/api/servers/create":
            self._create_server(body)
            return

        if path == "/api/servers/join":
            self._join_server(body)
            return

        if path == "/api/accounts/login":
            self._account_login(body)
            return

        if path == "/api/accounts/logout":
            token = self.headers.get("X-Account-Token", "").strip()
            if token:
                with db() as conn:
                    conn.execute("DELETE FROM account_sessions WHERE token_hash=?", (sha256_hex(token),))
            self._send_json(200, {"ok": True})
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

        if path == "/api/messages/edit":
            device = self._require_device()
            if device is None:
                return
            self._edit_message(device, body)
            return

        if path == "/api/messages/delete":
            device = self._require_device()
            if device is None:
                return
            self._delete_message(device, body)
            return

        if path == "/api/messages/react":
            device = self._require_device()
            if device is None:
                return
            self._react_message(device, body)
            return

        if path == "/api/messages/pin":
            device = self._require_device()
            if device is None:
                return
            self._pin_message(device, body)
            return

        if path == "/api/rooms/manage":
            device = self._require_device()
            if device is None:
                return
            if not ROOM_ADMIN_KEY:
                self._error(403, "configure TERMINUS_ROOM_ADMIN_KEY to enable group rename/delete")
                return
            supplied_key = str(body.get("admin_key") or "")
            if not hmac.compare_digest(supplied_key, ROOM_ADMIN_KEY):
                self._error(403, "host group-management key required or invalid")
                return
            action = str(body.get("action") or "").strip().lower()
            room_id = str(body.get("room_id") or "").strip()
            if not room_id or room_id == "general":
                self._error(400, "a non-general room_id is required")
                return
            if action == "rename":
                name = " ".join(str(body.get("name") or "").split())[:32]
                description = " ".join(str(body.get("description") or "").split())[:120]
                if not name:
                    self._error(400, "name required")
                    return
                with db() as conn:
                    cur = conn.execute("UPDATE rooms SET name=?, description=? WHERE id=?", (name, description, room_id))
                    if cur.rowcount == 0:
                        self._error(404, "room not found")
                        return
                    row = conn.execute("SELECT id, name, description, created_at FROM rooms WHERE id=?", (room_id,)).fetchone()
                with MESSAGE_COND:
                    MESSAGE_COND.notify_all()
                self._send_json(200, dict(row))
                return
            if action == "delete":
                with db() as conn:
                    exists = conn.execute("SELECT 1 FROM rooms WHERE id=?", (room_id,)).fetchone()
                    if not exists:
                        self._error(404, "room not found")
                        return
                    conn.execute("DELETE FROM messages WHERE room_id=?", (room_id,))
                    conn.execute("DELETE FROM rooms WHERE id=?", (room_id,))
                with MESSAGE_COND:
                    MESSAGE_COND.notify_all()
                self._send_json(200, {"ok": True, "deleted": room_id})
                return
            self._error(400, "action must be rename or delete")
            return

        if path == "/api/rooms":
            device = self._require_device()
            if device is None:
                return
            if ROOM_ADMIN_KEY:
                supplied_key = str(body.get("admin_key") or "")
                if not hmac.compare_digest(supplied_key, ROOM_ADMIN_KEY):
                    self._error(403, "host group-management key required or invalid")
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

    def _account_register(self, body: dict) -> None:
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        if not (3 <= len(username) <= 24) or not all(ch.isalnum() or ch in "_-" for ch in username):
            self._error(400, "Username must be 3–24 characters using letters, numbers, _ or -.")
            return
        if len(password) < 10 or len(password) > 256:
            self._error(400, "Password must be between 10 and 256 characters.")
            return
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
        account_id = "usr_" + secrets.token_hex(12)
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO accounts(id, username, password_salt, password_hash, created_at) VALUES(?,?,?,?,?)",
                    (account_id, username, salt, password_hash, now_iso()),
                )
        except sqlite3.IntegrityError:
            self._error(409, "That username is already registered.")
            return
        with db() as conn:
            server = conn.execute("SELECT id, owner_account_id FROM servers ORDER BY created_at ASC LIMIT 1").fetchone()
            if server and server["owner_account_id"] is None:
                conn.execute("UPDATE servers SET owner_account_id=? WHERE id=?", (account_id, server["id"]))
                conn.execute(
                    "INSERT OR IGNORE INTO server_members(server_id, account_id, role, joined_at) VALUES(?,?,?,?)",
                    (server["id"], account_id, "owner", now_iso()),
                )
        self._create_account_session(account_id, username)

    def _account_login(self, body: dict) -> None:
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        with db() as conn:
            account = conn.execute(
                "SELECT id, username, password_salt, password_hash FROM accounts WHERE username=? COLLATE NOCASE",
                (username,),
            ).fetchone()
        # Perform a KDF even for unknown usernames to reduce timing-based enumeration.
        salt = account["password_salt"] if account else b"\x00" * 16
        expected = account["password_hash"] if account else b"\x00" * 32
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8")[:256], salt, 600_000)
        if account is None or not hmac.compare_digest(actual, expected):
            self._error(401, "Incorrect username or password.")
            return
        with db() as conn:
            server = conn.execute("SELECT id, owner_account_id FROM servers ORDER BY created_at ASC LIMIT 1").fetchone()
            if server and server["owner_account_id"] is None:
                conn.execute("UPDATE servers SET owner_account_id=? WHERE id=?", (account["id"], server["id"]))
                conn.execute(
                    "INSERT OR IGNORE INTO server_members(server_id, account_id, role, joined_at) VALUES(?,?,?,?)",
                    (server["id"], account["id"], "owner", now_iso()),
                )
        self._create_account_session(account["id"], account["username"])

    def _create_account_session(self, account_id: str, username: str) -> None:
        token = "ta_" + secrets.token_urlsafe(40)
        with db() as conn:
            conn.execute(
                "INSERT INTO account_sessions(token_hash, account_id, created_at, expires_at) VALUES(?,?,?,?)",
                (sha256_hex(token), account_id, now_iso(), int(time.time()) + 30 * 24 * 60 * 60),
            )
        self._send_json(200, {
            "account_token": token,
            "account": {"id": account_id, "username": username},
            "expires_in": 30 * 24 * 60 * 60,
        })

    def _pair(self, body: dict) -> None:
        account_id = self._account_session_id()
        if account_id is None:
            self._error(401, "Sign in or create an account before pairing this device.")
            return
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
                "INSERT INTO devices(id, name, token_hash, created_at, last_seen, account_id) "
                "VALUES(?,?,?,?,?,?)",
                (device_id, name, sha256_hex(token), now_iso(), now_iso(), account_id),
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
        reply_to_id = body.get("reply_to_id")
        try:
            reply_to_id = int(reply_to_id) if reply_to_id is not None else None
        except (TypeError, ValueError):
            self._error(400, "invalid reply target")
            return
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
            room = conn.execute(
                """SELECT r.server_id, sm.role FROM rooms r JOIN server_members sm ON sm.server_id=r.server_id
                   WHERE r.id=? AND sm.account_id=?""",
                (room_id, device["account_id"]),
            ).fetchone()
            if room is None:
                self._error(404, "channel not found or you are not a member")
                return
            if reply_to_id is not None and not conn.execute(
                "SELECT 1 FROM messages WHERE id=? AND room_id=? AND deleted_at IS NULL",
                (reply_to_id, room_id),
            ).fetchone():
                self._error(404, "reply target not found")
                return
            try:
                cur = conn.execute(
                    "INSERT INTO messages(room_id, device_id, client_msg_id, nonce, ciphertext, created_at, reply_to_id) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (room_id, device["id"], client_msg_id, nonce, ciphertext, now_iso(), reply_to_id),
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

    def _edit_message(self, device: sqlite3.Row, body: dict) -> None:
        try:
            message_id = int(body.get("message_id"))
            nonce = b64d(str(body.get("nonce") or ""))
            ciphertext = b64d(str(body.get("ciphertext") or ""))
        except (TypeError, ValueError):
            self._error(400, "invalid message edit")
            return
        if len(nonce) != 12 or not ciphertext or len(ciphertext) > MAX_CIPHERTEXT:
            self._error(400, "invalid ciphertext")
            return
        with db() as conn:
            row = conn.execute("SELECT device_id, deleted_at FROM messages WHERE id=?", (message_id,)).fetchone()
            if row is None or row["deleted_at"]:
                self._error(404, "message not found")
                return
            if row["device_id"] != device["id"]:
                self._error(403, "only the author can edit this message")
                return
            conn.execute("UPDATE messages SET nonce=?, ciphertext=?, edited_at=? WHERE id=?",
                         (nonce, ciphertext, now_iso(), message_id))
        with MESSAGE_COND:
            MESSAGE_COND.notify_all()
        self._send_json(200, {"ok": True, "message_id": message_id})

    def _delete_message(self, device: sqlite3.Row, body: dict) -> None:
        try:
            message_id = int(body.get("message_id"))
        except (TypeError, ValueError):
            self._error(400, "message_id required")
            return
        with db() as conn:
            row = conn.execute("SELECT device_id, deleted_at FROM messages WHERE id=?", (message_id,)).fetchone()
            if row is None or row["deleted_at"]:
                self._error(404, "message not found")
                return
            if row["device_id"] != device["id"]:
                self._error(403, "only the author can delete this message")
                return
            conn.execute("UPDATE messages SET deleted_at=?, ciphertext=?, nonce=? WHERE id=?",
                         (now_iso(), b"", secrets.token_bytes(12), message_id))
            conn.execute("DELETE FROM reactions WHERE message_id=?", (message_id,))
        with MESSAGE_COND:
            MESSAGE_COND.notify_all()
        self._send_json(200, {"ok": True, "message_id": message_id, "deleted": True})

    def _react_message(self, device: sqlite3.Row, body: dict) -> None:
        try:
            message_id = int(body.get("message_id"))
        except (TypeError, ValueError):
            self._error(400, "message_id required")
            return
        emoji = str(body.get("emoji") or "").strip()
        if not emoji or len(emoji) > 16:
            self._error(400, "choose a valid reaction")
            return
        account_id = self._account_session_id()
        with db() as conn:
            if not conn.execute("SELECT 1 FROM messages WHERE id=? AND deleted_at IS NULL", (message_id,)).fetchone():
                self._error(404, "message not found")
                return
            existing = conn.execute(
                "SELECT 1 FROM reactions WHERE message_id=? AND account_id=? AND emoji=?",
                (message_id, account_id, emoji),
            ).fetchone()
            if existing:
                conn.execute("DELETE FROM reactions WHERE message_id=? AND account_id=? AND emoji=?",
                             (message_id, account_id, emoji))
                active = False
            else:
                conn.execute("INSERT INTO reactions(message_id, account_id, emoji, created_at) VALUES(?,?,?,?)",
                             (message_id, account_id, emoji, now_iso()))
                active = True
            conn.execute("UPDATE messages SET edited_at=? WHERE id=?", (now_iso(), message_id))
            rows = conn.execute("SELECT emoji, COUNT(*) AS count FROM reactions WHERE message_id=? GROUP BY emoji",
                                (message_id,)).fetchall()
        with MESSAGE_COND:
            MESSAGE_COND.notify_all()
        self._send_json(200, {"ok": True, "active": active, "reactions": [dict(r) for r in rows]})

    def _pin_message(self, device: sqlite3.Row, body: dict) -> None:
        try:
            message_id = int(body.get("message_id"))
        except (TypeError, ValueError):
            self._error(400, "message_id required")
            return
        pinned = bool(body.get("pinned", True))
        with db() as conn:
            row = conn.execute("SELECT deleted_at FROM messages WHERE id=?", (message_id,)).fetchone()
            if row is None or row["deleted_at"]:
                self._error(404, "message not found")
                return
            conn.execute("UPDATE messages SET pinned=?, edited_at=? WHERE id=?", (1 if pinned else 0, now_iso(), message_id))
        with MESSAGE_COND:
            MESSAGE_COND.notify_all()
        self._send_json(200, {"ok": True, "message_id": message_id, "pinned": pinned})

    def _create_server(self, body: dict) -> None:
        account_id = self._account_session_id()
        if account_id is None:
            self._error(401, "sign in first")
            return
        name = " ".join(str(body.get("name") or "").split())[:48]
        description = " ".join(str(body.get("description") or "").split())[:160]
        if not name:
            self._error(400, "server name required")
            return
        server_id = "srv_" + secrets.token_hex(6)
        invite_code = secrets.token_urlsafe(9)
        with db() as conn:
            conn.execute(
                "INSERT INTO servers(id,name,description,invite_code,owner_account_id,created_at) VALUES(?,?,?,?,?,?)",
                (server_id, name, description, invite_code, account_id, now_iso()),
            )
            conn.execute(
                "INSERT INTO server_members(server_id,account_id,role,joined_at) VALUES(?,?,?,?)",
                (server_id, account_id, "owner", now_iso()),
            )
            conn.execute(
                "INSERT INTO rooms(id,name,description,created_at,server_id) VALUES(?,?,?,?,?)",
                (server_id + "_general", "general", "General chat", now_iso(), server_id),
            )
        self._send_json(200, {"id": server_id, "name": name, "description": description, "invite_code": invite_code, "role": "owner"})

    def _join_server(self, body: dict) -> None:
        account_id = self._account_session_id()
        if account_id is None:
            self._error(401, "sign in first")
            return
        code = str(body.get("invite_code") or "").strip()
        if not code:
            self._error(400, "invite code required")
            return
        with db() as conn:
            server = conn.execute("SELECT id,name,description FROM servers WHERE invite_code=?", (code,)).fetchone()
            if server is None:
                self._error(404, "invalid invite code")
                return
            conn.execute(
                "INSERT OR IGNORE INTO server_members(server_id,account_id,role,joined_at) VALUES(?,?,?,?)",
                (server["id"], account_id, "member", now_iso()),
            )
            member = conn.execute("SELECT role FROM server_members WHERE server_id=? AND account_id=?",
                                  (server["id"], account_id)).fetchone()
        self._send_json(200, {"id": server["id"], "name": server["name"], "description": server["description"], "role": member["role"]})

    def _create_room(self, device: sqlite3.Row, body: dict) -> None:
        name = " ".join(str(body.get("name") or "").split())[:32]
        description = " ".join(str(body.get("description") or "").split())[:120]
        if not name:
            self._error(400, "name required")
            return
        server_id = str(body.get("server_id") or "").strip()
        if not server_id:
            self._error(400, "server_id required")
            return
        with db() as conn:
            member = conn.execute(
                "SELECT role FROM server_members WHERE server_id=? AND account_id=?",
                (server_id, device["account_id"]),
            ).fetchone()
            if member is None:
                self._error(403, "join this server first")
                return
            if member["role"] not in ("owner", "admin"):
                self._error(403, "only server owners and admins can create channels")
                return
            room_id = "r_" + secrets.token_hex(5)
            conn.execute(
                "INSERT INTO rooms(id, name, description, created_at, server_id) VALUES(?,?,?,?,?)",
                (room_id, name, description, now_iso(), server_id),
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
    global DATA_DIR, DB_PATH, PAIR_CODE, MASTER_KEY, ROOM_ADMIN_KEY, CERT_FINGERPRINT, LAN_IP, SERVER_NAME, PUBLIC_URL

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
    ROOM_ADMIN_KEY = os.environ.get("TERMINUS_ROOM_ADMIN_KEY", "").strip()
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
    # Channel administration defaults to the host master key. An explicit
    # TERMINUS_ROOM_ADMIN_KEY may be used for deployments that need a separate key.
    ROOM_ADMIN_KEY = os.environ.get("TERMINUS_ROOM_ADMIN_KEY", "").strip() or MASTER_KEY

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
