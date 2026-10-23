"""Source-level regression checks for reconnect and resource-estimate contracts."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "server" / "web" / "app.js").read_text(encoding="utf-8")
ANDROID = (ROOT / "android-app" / "app" / "src" / "main" / "java" / "com" / "terminus" / "secrets" / "MainActivity.java").read_text(encoding="utf-8")
SETTINGS = (ROOT / "server" / "settings_app.py").read_text(encoding="utf-8")

reconnect_start = APP.index('if (params.get("tsReconnect") === "1")')
reconnect_end = APP.index("if (encoded || params.has(\"tsReconnect\"))", reconnect_start)
reconnect = APP[reconnect_start:reconnect_end]
assert "localStorage.removeItem(LS.token)" in reconnect
assert "localStorage.removeItem(LS.device)" in reconnect
assert "localStorage.removeItem(LS.accountToken)" not in reconnect
assert "localStorage.removeItem(LS.account)" not in reconnect
assert "await fetch(\"/api/devices/revoke\"" in reconnect

assert "pendingNotificationRoom = safeRoom" in ANDROID
assert "requestCode == NOTIFICATION_PERMISSION_REQUEST" in ANDROID
assert "if (granted && !room.isEmpty()) showMessageNotification(room)" in ANDROID
assert "Local clients on this PC" in SETTINGS
assert "Media sessions on this PC" in SETTINGS
assert "Estimated CPU on 12th-gen Intel Core i5" in SETTINGS
assert "Estimated RTX 3050 4 GB VRAM (local client only)" in SETTINGS
assert "not live telemetry" in SETTINGS

print("Reconnect, Android notification permission, and resource-estimate source checks passed.")
