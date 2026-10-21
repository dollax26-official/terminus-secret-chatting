import asyncio
import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import sys
import websockets
sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_screenshots import CDP, EDGE, ROOT

PORT = 9226


async def main():
    profile = ROOT / ".screens" / "edge-crypto-cdp"
    shutil.rmtree(profile, ignore_errors=True)
    process = subprocess.Popen(
        [
            str(EDGE),
            "--no-sandbox",
            "--ignore-certificate-errors",
            "--no-first-run",
            "--window-size=900,700",
            f"--remote-debugging-port={PORT}",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        targets = None
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2) as response:
                    targets = json.loads(response.read())
                if any(t.get("type") == "page" for t in targets):
                    break
            except Exception:
                pass
            time.sleep(0.3)
        page = next(t for t in targets if t.get("type") == "page")
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=8 * 1024 * 1024) as ws:
            cdp = CDP(ws)
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")
            await cdp.call("Page.navigate", {"url": "https://127.0.0.1:8444/app/cryptotest.html"})
            await asyncio.sleep(4)
            result = await cdp.evaluate("document.getElementById('out') ? document.getElementById('out').textContent : 'missing'")
            print("RESULT:", result)
            secure = await cdp.evaluate("({secure: window.isSecureContext, subtle: !!crypto.subtle, origin: location.origin})")
            print("CONTEXT:", secure)

            checks = [
                ("digest", "crypto.subtle.digest('SHA-256', new Uint8Array([1,2,3])).then(b => 'ok ' + b.byteLength)"),
                ("import", "crypto.subtle.importKey('raw', new TextEncoder().encode('abc'), 'PBKDF2', false, ['deriveKey']).then(() => 'ok')"),
                ("derive", "(async () => { const k = await crypto.subtle.importKey('raw', new TextEncoder().encode('abc'), 'PBKDF2', false, ['deriveKey']); await crypto.subtle.deriveKey({name:'PBKDF2', salt:new Uint8Array(16), iterations:1000, hash:'SHA-256'}, k, {name:'AES-GCM', length:256}, false, ['encrypt']); return 'ok'; })()"),
            ]
            for label, expression in checks:
                try:
                    value = await asyncio.wait_for(cdp.evaluate(expression, await_promise=True), timeout=8)
                    print(label, value)
                except Exception as exc:
                    print(label, "TIMEOUT", exc)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


asyncio.run(main())
