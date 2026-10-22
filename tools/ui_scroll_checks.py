"""Static regression checks for scroll containers in the host manager and shared client."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "server" / "web" / "styles.css").read_text(encoding="utf-8")
HOST_UI = (ROOT / "server" / "settings_app.py").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"UI scroll regression: {message}")


require("#chatView .messages" in CSS and "overflow-y: auto" in CSS, "chat timeline must be vertically scrollable")
require("-webkit-overflow-scrolling: touch" in CSS, "touch scrolling must be enabled for mobile WebViews")
require("touch-action: pan-y" in CSS, "vertical touch gestures must not be suppressed")
require("#connectView.connect" in CSS and "overscroll-behavior-y: contain" in CSS, "connect form needs its own scrollport")
require("#chatView .rail" in CSS and "#chatView .rooms" in CSS, "sidebar and channel lists need independent scrollports")
require("tk.Canvas" in HOST_UI and "yscrollcommand=self.scrollbar.set" in HOST_UI, "host manager needs a scrollable canvas")
require("self.canvas.yview_scroll" in HOST_UI and "self._bind_scroll_events(outer)" in HOST_UI, "host manager must scroll when the pointer is over child controls")
require('self.root.bind_all(sequence, self._on_mousewheel, add="+")' in HOST_UI, "host manager needs a wheel-event fallback for Tk child widgets")
print("UI scroll checks passed.")
