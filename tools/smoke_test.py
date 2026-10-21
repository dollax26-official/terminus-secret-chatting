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


def request(path, method="GET", token=None, payload=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
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
        assert row["device_name"] == "Windows desk"
        assert decrypt(key, "general", row["nonce"], row["ciphertext"]) == secret_text

        # A second sync after the last id must be empty.
        empty = get_json(f"/api/sync?after={sync['last_id']}&wait=0", token=device_b["token"])
        assert empty["messages"] == []

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
