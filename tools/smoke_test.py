"""End-to-end protocol test for the Terminus Secrets host.

Starts a throwaway host, pairs two devices, sends encrypted messages through the
real HTTP API, and verifies that the database on disk contains no plaintext.
"""

import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "server" / "host.py"
DATA = ROOT / ".testdata"
PORT = 9553
BASE = f"https://127.0.0.1:{PORT}"
CTX = ssl._create_unverified_context()
ACCOUNT_TOKEN = ""


def request(path, method="GET", token=None, payload=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if ACCOUNT_TOKEN:
        headers["X-Account-Token"] = ACCOUNT_TOKEN
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=CTX, timeout=30) as response:
        return response.status, dict(response.headers), response.read()


def get_json(path, token=None):
    return json.loads(request(path, token=token)[2])


def encrypt(key, room, text):
    nonce = os.urandom(12)
    aad = f"terminus-secrets:v1:{room}".encode()
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps({"t": "text", "b": text}).encode(), aad)
    return base64.b64encode(nonce).decode(), base64.b64encode(ciphertext).decode()


def decrypt(key, room, nonce_b64, ct_b64):
    aad = f"terminus-secrets:v1:{room}".encode()
    clear = AESGCM(key).decrypt(
        base64.b64decode(nonce_b64), base64.b64decode(ct_b64), aad
    )
    return json.loads(clear)["b"]


def main():
    shutil.rmtree(DATA, ignore_errors=True)
    process = subprocess.Popen(
        [sys.executable, str(HOST), "--port", str(PORT), "--data-dir", str(DATA)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        for _ in range(80):
            try:
                status, _, body = request("/api/health")
                if status == 200:
                    break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("host did not start")

        health = json.loads(body)
        assert health["app"] == "terminus-secrets"
        assert health["fingerprint"].count(":") == 31

        global ACCOUNT_TOKEN
        _, _, account_body = request(
            "/api/accounts/register",
            method="POST",
            payload={"username": "smoke_tester", "password": "smoke-test-password-123"},
        )
        account = json.loads(account_body)
        ACCOUNT_TOKEN = account["account_token"]
        assert account["account"]["username"] == "smoke_tester"

        try:
            request("/api/accounts/register", method="POST",
                    payload={"username": "SMOKE_TESTER", "password": "duplicate-name-password-123"})
            raise AssertionError("duplicate username was accepted")
        except urllib.error.HTTPError as exc:
            assert exc.code == 409, exc.code

        code = (DATA / "pairing-code.txt").read_text().strip()
        assert len(code) == 9

        try:
            request("/api/sync", token="ts_invalid_token_0000000000")
            raise AssertionError("invalid token was accepted")
        except urllib.error.HTTPError as exc:
            assert exc.code == 401, exc.code

        try:
            request("/api/pair", method="POST", payload={"code": "0000-0000", "device_name": "bad"})
            raise AssertionError("wrong pairing code was accepted")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403, exc.code

        _, _, body = request(
            "/api/pair", method="POST", payload={"code": code, "device_name": "Windows desk"}
        )
        device_a = json.loads(body)
        assert device_a["token"].startswith("ts_")

        _, _, body = request(
            "/api/pair", method="POST", payload={"code": code, "device_name": "Android phone"}
        )
        device_b = json.loads(body)
        assert device_b["device_id"] != device_a["device_id"]

        vault = get_json("/api/vault", token=device_a["token"])
        salt = base64.b64decode(vault["salt"])
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=vault["iterations"]
        ).derive((DATA / "vault-passphrase.txt").read_text().strip().encode())

        secret_text = "launch code is ORBIT-9 \u2014 do not share"
        nonce, ciphertext = encrypt(key, "general", secret_text)
        status, _, body = request(
            "/api/messages",
            method="POST",
            token=device_a["token"],
            payload={
                "room_id": "general",
                "client_msg_id": "smoke-1",
                "nonce": nonce,
                "ciphertext": ciphertext,
            },
        )
        assert status == 200, body

        sync = get_json("/api/sync?after=0&wait=0", token=device_b["token"])
        assert sync["rooms"][0]["id"] == "general"
        assert len(sync["messages"]) == 1
        row = sync["messages"][0]
        assert row["device_name"] == "smoke_tester"
        assert decrypt(key, "general", row["nonce"], row["ciphertext"]) == secret_text

        # A second sync after the last id must be empty.
        empty = get_json(f"/api/sync?after={sync['last_id']}&wait=0", token=device_b["token"])
        assert empty["messages"] == []

        # Exercise multi-server channels, private membership, roles, and DMs.
        account1_token = ACCOUNT_TOKEN
        _, _, server_body = request(
            "/api/servers/create", method="POST",
            payload={"name": "Protocol Test Server", "description": "smoke test"},
        )
        server = json.loads(server_body)
        assert server["role"] == "owner" and server["invite_code"]

        _, _, public_body = request(
            "/api/rooms", method="POST", token=device_a["token"],
            payload={"server_id": server["id"], "name": "announcements", "category": "Community"},
        )
        public_room = json.loads(public_body)
        assert public_room["category"] == "Community" and public_room["kind"] == "text"

        _, _, private_body = request(
            "/api/rooms", method="POST", token=device_a["token"],
            payload={"server_id": server["id"], "name": "staff", "category": "Staff", "private": True},
        )
        private_room = json.loads(private_body)
        assert private_room["kind"] == "private"

        _, _, other_body = request(
            "/api/accounts/register", method="POST",
            payload={"username": "smoke_other", "password": "another-smoke-password-456"},
        )
        other_account = json.loads(other_body)
        ACCOUNT_TOKEN = other_account["account_token"]
        request("/api/servers/join", method="POST", payload={"invite_code": server["invite_code"]})
        _, _, other_device_body = request(
            "/api/pair", method="POST", payload={"code": code, "device_name": "Other phone"}
        )
        other_device = json.loads(other_device_body)

        # Authenticated WebRTC signaling can only be sent between users who
        # share a server; recipients receive the signal through their own session.
        ACCOUNT_TOKEN = account1_token
        _, _, signal_body = request(
            "/api/calls/signal", method="POST", token=device_a["token"],
            payload={"to_username": "smoke_other", "call_id": "call-smoke-1",
                     "kind": "offer", "payload": {"mode": "audio", "description": {"type": "offer", "sdp": "test-sdp"}}},
        )
        assert json.loads(signal_body)["ok"] is True
        ACCOUNT_TOKEN = other_account["account_token"]
        call_signals = get_json("/api/calls/signals?after=0", token=other_device["token"])["signals"]
        assert len(call_signals) == 1
        assert call_signals[0]["from_username"] == "smoke_tester"
        assert call_signals[0]["kind"] == "offer"
        ACCOUNT_TOKEN = account1_token

        _, _, dm_body = request(
            "/api/dm/open", method="POST", token=device_a["token"],
            payload={"username": "smoke_other"},
        )
        dm = json.loads(dm_body)
        dm_nonce, dm_ciphertext = encrypt(key, dm["id"], "private direct message")
        request(
            "/api/messages", method="POST", token=device_a["token"],
            payload={"room_id": dm["id"], "client_msg_id": "dm-smoke-1",
                     "nonce": dm_nonce, "ciphertext": dm_ciphertext},
        )

        ACCOUNT_TOKEN = other_account["account_token"]
        other_sync = get_json("/api/sync?after=0&wait=0", token=other_device["token"])
        other_room_ids = {room["id"] for room in other_sync["rooms"]}
        assert public_room["id"] in other_room_ids
        assert private_room["id"] not in other_room_ids
        assert dm["id"] in other_room_ids
        dm_rows = [row for row in other_sync["messages"] if row["room_id"] == dm["id"]]
        assert len(dm_rows) == 1
        assert decrypt(key, dm["id"], dm_rows[0]["nonce"], dm_rows[0]["ciphertext"]) == "private direct message"
        assert next(server_row for server_row in other_sync["servers"] if server_row["id"] == server["id"])["role"] == "member"

        ACCOUNT_TOKEN = account1_token
        _, _, role_body = request(
            "/api/servers/role", method="POST", token=device_a["token"],
            payload={"server_id": server["id"], "username": "smoke_other", "role": "admin"},
        )
        assert json.loads(role_body)["role"] == "admin"
        ACCOUNT_TOKEN = other_account["account_token"]
        admin_sync = get_json("/api/sync?after=0&wait=0", token=other_device["token"])
        admin_room_ids = {room["id"] for room in admin_sync["rooms"]}
        assert private_room["id"] in admin_room_ids
        assert next(server_row for server_row in admin_sync["servers"] if server_row["id"] == server["id"])["role"] == "admin"
        ACCOUNT_TOKEN = account1_token

        # Vault check blob round-trip (the web client stores a known marker).
        marker_nonce = os.urandom(12)
        marker_ct = AESGCM(key).encrypt(
            marker_nonce, b"terminus-vault-v1", b"terminus-secrets:vault-check:v1"
        )
        request(
            "/api/vault/check",
            method="POST",
            token=device_a["token"],
            payload={
                "nonce": base64.b64encode(marker_nonce).decode(),
                "ciphertext": base64.b64encode(marker_ct).decode(),
            },
        )
        check = get_json("/api/vault", token=device_b["token"])["check"]
        assert check is not None
        assert (
            AESGCM(key).decrypt(
                base64.b64decode(check["nonce"]),
                base64.b64decode(check["ciphertext"]),
                b"terminus-secrets:vault-check:v1",
            )
            == b"terminus-vault-v1"
        )

        # At-rest check: no plaintext anywhere in the data directory.
        for path in DATA.rglob("*"):
            if path.is_file():
                blob = path.read_bytes()
                assert b"ORBIT-9" not in blob, f"plaintext leaked into {path}"
                assert b"launch code" not in blob, f"plaintext leaked into {path}"

        status, headers, page = request("/app/")
        assert status == 200
        assert b"Terminus Secrets" in page
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")

        print("PASS  host, pairing, auth, encryption, sync, at-rest, static UI")
        print(f"      devices={len(sync['devices'])} messages={len(sync['messages'])}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    main()
