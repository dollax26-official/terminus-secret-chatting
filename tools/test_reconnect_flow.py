"""Source-level regression checks for reconnect and resource-estimate contracts."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "server" / "web" / "app.js").read_text(encoding="utf-8")
ANDROID = (ROOT / "android-app" / "app" / "src" / "main" / "java" / "com" / "terminus" / "secrets" / "MainActivity.java").read_text(encoding="utf-8")
WINDOWS = (ROOT / "windows-app" / "electron" / "main.js").read_text(encoding="utf-8")
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
assert '("Vault phrase", self.vault_phrase_var)' in SETTINGS
assert '("Pairing code", self.pairing_code_var)' in SETTINGS
assert '("Master key", self.master_key_var)' in SETTINGS
assert 'read_secret("master-key.txt")' in SETTINGS
assert "def _copy_secret(self, value: str, label: str)" in SETTINGS
assert '["clip.exe"]' in SETTINGS
assert "def _report_start(self)" in SETTINGS
assert "self.root.after(500, self._report_start)" in SETTINGS
assert "self.vault_phrase and self.pairing_code and self.master_key" in SETTINGS
assert "async function copyTextToClipboard" in APP
assert "window.TerminusNative.copyText(text)" in APP
assert "function updateJump()" in APP
assert "ui.messages.scrollTop = previousTop" in APP
assert "@JavascriptInterface\n        public boolean copyText(String value)" in ANDROID
# WebView must not grant mic/camera permission to an untrusted origin.
assert "Uri requestedOrigin = request.getOrigin();" in ANDROID
assert "boolean trustedOrigin = requestedOrigin != null" in ANDROID
assert '"https".equalsIgnoreCase(requestedOrigin.getScheme())' in ANDROID
assert "effectivePort(requestedOrigin) == effectivePort(configuredOrigin)" in ANDROID
assert "if (!trustedOrigin)" in ANDROID
# Windows Electron must explicitly grant media only to the bundled loopback client.
assert "session.defaultSession.setPermissionRequestHandler" in WINDOWS
assert "const trustedClient = Boolean(webContents && !webContents.isDestroyed() && isLocal(requestingUrl));" in WINDOWS
assert 'permission === "media" || permission === "display-capture"' in WINDOWS
assert "callback(allowed);" in WINDOWS
assert "private static int effectivePort(Uri uri)" in ANDROID
assert "public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request)" in ANDROID
assert "if (trustedOrigin) return false;" in ANDROID
assert "Never load HTTP, other hosts, alternate ports, or custom schemes inside" in ANDROID
assert "return true;" in ANDROID
assert "ClipboardManager clipboard" in ANDROID
assert "Each file is independent and credentials are refreshed while the host" in SETTINGS
assert 'read_secret("master-key.txt")' in SETTINGS
assert "async function copyTextToClipboard" in APP
assert "if (!copied) toast(" in APP

print("Reconnect, credential copy, Android notification permission, clipboard fallback, and resource-estimate source checks passed.")

assert 'state.authMethod = "code";' in APP
assert 'setAuthMethod("code");' in APP

HTML = (ROOT / "server" / "web" / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "server" / "web" / "styles.css").read_text(encoding="utf-8")
assert 'placeholder="007EE4-9B4BA6" maxlength="13"' in HTML
assert "Normalize typed or pasted pairing codes" in APP
assert 'slice(0, 12)' in APP and 'raw.slice(0, 6)}-${raw.slice(6)' in APP
assert "Match the optimistic message even if POST already replaced its" in APP
assert "grid-template-columns: minmax(240px, 288px) minmax(0, 1fr);" in CSS
assert "#chatView.app > .rail {\n  grid-column: 1;" in CSS
assert "#chatView.app > .stage {\n  grid-column: 2;" in CSS
assert "#chatView #roomList" in CSS

# UI and real media-action regression checks.
assert 'id="settingsBtn"' not in HTML
assert 'id="settingsDialog"' not in HTML
assert 'Appearance settings' not in HTML
assert 'settingsBtn' not in APP and 'settingsDialog' not in APP
assert "file.size > 60 * 1024" in APP
assert "new MediaRecorder(stream" in APP
assert 'sendText("__TS_ATTACHMENT_V1__:"' in APP
assert 'player.controls = true' in APP
assert 'new RTCPeerConnection' in APP
assert '"/api/calls/signal"' in APP
assert '"/api/calls/poll?after=' in APP
assert "ui.shareCallBtn.disabled = !navigator.mediaDevices?.getDisplayMedia;" in APP
assert "prefers-reduced-motion: reduce" in CSS

print("Appearance removal, attachment/voice-message rendering, call signaling, and motion accessibility checks passed.")
