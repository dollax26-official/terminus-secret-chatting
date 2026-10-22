"""Regression checks for scroll reachability in the shared chat UI and host manager."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "server" / "web" / "styles.css").read_text(encoding="utf-8")
HOST_UI = (ROOT / "server" / "settings_app.py").read_text(encoding="utf-8")

required_css = (
    "#connectView.connect", "#chatView .messages", "#chatView .rail",
    "#chatView .rooms", "overflow-y:auto", "-webkit-overflow-scrolling:touch",
    "touch-action:pan-y", ".messages > * { flex-shrink:0; }",
)
required_host = (
    "self.canvas = tk.Canvas",
    'self.canvas.yview_scroll(units, "units")',
    "self._bind_scroll_events(outer)",
    'self.root.bind_all(sequence, self._on_mousewheel, add="+")',
)
missing = [f"styles.css missing {item!r}" for item in required_css if item not in CSS]
missing += [f"settings_app.py missing {item!r}" for item in required_host if item not in HOST_UI]
if missing:
    raise SystemExit("\n".join(missing))
print("UI scroll regression checks passed.")
