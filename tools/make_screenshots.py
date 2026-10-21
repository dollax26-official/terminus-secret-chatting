"""Capture real UI screenshots from the running host using Edge + CDP.

Assumes host.py is running on https://127.0.0.1:8443 with .devdata.
"""

import asyncio
import base64
import json
import os
import shutil
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path

import websockets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(r"C:\Users\mohsen\.openclaw-autoclaw\workspace\terminus-secrets")
BASE = os.environ.get("TERMINUS_SHOT_BASE", "https://127.0.0.1:8443")
DATA = Path(os.environ.get("TERMINUS_SHOT_DATA", str(ROOT / ".devdata")))
OUT = ROOT / "screenshots"
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
PORT = 9223
CTX = ssl._create_unverified_context()


def api(path, method="GET", auth=None, payload=None):
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if auth:
        headers["Authorization"] = "Bearer " + auth
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=CTX, timeout=20) as response:
        return json.loads(response.read())


def post_phone_messages():
    code = (DATA / "pairing-code.txt").read_text().strip()
    phone = api("/api/pair", "POST", payload={"code": code, "device_name": "Pixel 9"})
    vault = api("/api/vault", auth=phone["token"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(vault["salt"]),
        iterations=vault["iterations"],
    ).derive((DATA / "vault-passphrase.txt").read_text().strip().encode())

    messages = [
        "Landed. The relay is only holding ciphertext on your laptop.",
        "Try the new channel — I left the launch note in #operations.",
    ]
    for index, text in enumerate(messages):
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            json.dumps({"t": "text", "b": text}).encode(),
            b"terminus-secrets:v1:general",
        )
        api(
            "/api/messages",
            "POST",
            auth=phone["token"],
            payload={
                "room_id": "general",
                "client_msg_id": f"shot-phone-{index}",
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            },
        )
    return phone


class CDP:
    def __init__(self, websocket):
        self.ws = websocket
        self.next_id = 1

    async def call(self, method, params=None):
        message_id = self.next_id
        self.next_id += 1
        await self.ws.send(json.dumps({"id": message_id, "method": method, "params": params or {}}))
        while True:
            raw = await self.ws.recv()
            data = json.loads(raw)
            if data.get("id") == message_id:
                if "error" in data:
                    raise RuntimeError(f"{method}: {data['error']}")
                return data.get("result", {})

    async def evaluate(self, expression, await_promise=False):
        return await self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": await_promise,
            },
        )

    async def wait_for(self, expression, timeout=25):
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = await self.evaluate(expression)
            if result.get("result", {}).get("value"):
                return True
            await asyncio.sleep(0.4)
        return False


async def main():
    OUT.mkdir(exist_ok=True)
    post_phone_messages()

    profile = ROOT / ".screens" / "edge-cdp"
    shutil.rmtree(profile, ignore_errors=True)
    process = subprocess.Popen(
        [
            str(EDGE),
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--ignore-certificate-errors",
            "--no-first-run",
            f"--remote-debugging-port={PORT}",
            f"--user-data-dir={profile}",
            "--window-size=1440,900",
            f"{BASE}/app/",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        targets = None
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2) as response:
                    targets = json.loads(response.read())
                if any(t.get("type") == "page" for t in targets):
                    break
            except Exception:
                pass
            time.sleep(0.4)
        if not targets:
            raise RuntimeError("Edge did not expose a debugging target")

        page = next(t for t in targets if t.get("type") == "page")
        code = (DATA / "pairing-code.txt").read_text().strip()
        phrase = (DATA / "vault-passphrase.txt").read_text().strip()

        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=8 * 1024 * 1024) as ws:
            cdp = CDP(ws)
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")
            await cdp.call(
                "Emulation.setDeviceMetricsOverride",
                {"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": False},
            )
            if not await cdp.wait_for("document.querySelector('#connectForm') !== null", 20):
                raise RuntimeError("connect form missing")

            await cdp.evaluate(
                "(() => {"
                f"document.querySelector('#codeInput').value = {json.dumps(code)};"
                f"document.querySelector('#passInput').value = {json.dumps(phrase)};"
                "document.querySelector('#deviceInput').value = 'Windows desk';"
                "document.querySelector('#connectForm').requestSubmit();"
                "return true;"
                "})()"
            )
            await cdp.wait_for("!document.querySelector('#chatView').hidden", 120)
            if await cdp.evaluate("document.querySelector('#chatView').hidden"):
                detail = await cdp.evaluate(
                    "JSON.stringify({err: document.querySelector('#connectError').textContent, "
                    "disabled: document.querySelector('#connectBtn').disabled, "
                    "label: document.querySelector('#connectBtn .btn-label').textContent})"
                )
                raise RuntimeError(f"chat did not open: {detail}")
            await asyncio.sleep(3)

            await cdp.evaluate(
                "(() => {"
                "const input = document.querySelector('#input');"
                "input.value = 'This is the desk. History is in one file on this laptop.';"
                "input.dispatchEvent(new Event('input', {bubbles: true}));"
                "document.querySelector('#composer').requestSubmit();"
                "return true;"
                "})()"
            )
            await asyncio.sleep(2)

            shot = await cdp.call("Page.captureScreenshot", {"format": "png"})
            (OUT / "chat-desktop.png").write_bytes(base64.b64decode(shot["data"]))

            await cdp.call(
                "Emulation.setDeviceMetricsOverride",
                {"width": 390, "height": 844, "deviceScaleFactor": 2, "mobile": True},
            )
            await asyncio.sleep(1.5)
            shot = await cdp.call("Page.captureScreenshot", {"format": "png"})
            (OUT / "chat-mobile.png").write_bytes(base64.b64decode(shot["data"]))

            await cdp.evaluate("localStorage.clear(); location.href='/app/';")
            await asyncio.sleep(2)
            shot = await cdp.call("Page.captureScreenshot", {"format": "png"})
            (OUT / "connect-mobile.png").write_bytes(base64.b64decode(shot["data"]))

        print("screenshots:", sorted(p.name for p in OUT.glob("*.png")))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    asyncio.run(main())
