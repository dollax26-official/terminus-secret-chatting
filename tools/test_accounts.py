#!/usr/bin/env python3
"""Regression tests for Terminus Secrets account registration and sessions."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
import host  # noqa: E402


def request(base: str, path: str, method: str = "GET", body: dict | None = None,
            account_token: str = "") -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if account_token:
        headers["X-Account-Token"] = account_token
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="terminus-account-test-") as temp:
        host.DATA_DIR = Path(temp)
        host.DB_PATH = host.DATA_DIR / "terminus.db"
        host.init_db("test-vault-passphrase")
        server = ThreadingHTTPServer(("127.0.0.1", 0), host.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            status, created = request(base, "/api/accounts/register", "POST", {
                "username": "signup_test_user",
                "password": "correct-horse-battery-staple",
                "display_name": "Signup Test",
            })
            assert status == 200, (status, created)
            assert created.get("account_token"), created
            assert created.get("account", {}).get("username") == "signup_test_user", created

            status, duplicate = request(base, "/api/accounts/register", "POST", {
                "username": "SIGNUP_TEST_USER",
                "password": "another-correct-password",
            })
            assert status == 409, (status, duplicate)

            # Unicode-aware casefold uniqueness is stricter than SQLite NOCASE.
            status, unicode_created = request(base, "/api/accounts/register", "POST", {
                "username": "Straße",
                "password": "unicode-casefold-password",
                "display_name": "Repeated display name",
            })
            assert status == 200, (status, unicode_created)
            status, unicode_duplicate = request(base, "/api/accounts/register", "POST", {
                "username": "STRASSE",
                "password": "another-long-password",
            })
            assert status == 409, (status, unicode_duplicate)
            status, unicode_login = request(base, "/api/accounts/login", "POST", {
                "username": "STRASSE",
                "password": "unicode-casefold-password",
            })
            assert status == 200 and unicode_login.get("account_token"), (status, unicode_login)

            status, session = request(base, "/api/accounts/session", account_token=created["account_token"])
            assert status == 200, (status, session)
            assert session.get("account", {}).get("id") == created["account"]["id"], session

            status, login = request(base, "/api/accounts/login", "POST", {
                "username": "SIGNUP_TEST_USER",
                "password": "correct-horse-battery-staple",
            })
            assert status == 200 and login.get("account_token"), (status, login)

            status, invalid = request(base, "/api/accounts/session", account_token="invalid-token")
            assert status == 401, (status, invalid)

            status, bad_password = request(base, "/api/accounts/register", "POST", {
                "username": "short_password_user",
                "password": "short",
            })
            assert status == 400, (status, bad_password)
            print("PASS: account registration, duplicate rejection, login, and session validation")
            return 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            # host.db() closes each SQLite connection; the temporary directory
            # can therefore be removed immediately on Windows as well.


if __name__ == "__main__":
    raise SystemExit(main())
