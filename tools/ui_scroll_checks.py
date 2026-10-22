"""Regression checks for scroll reachability in the shared chat UI and host manager."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "server" / "web" / "styles.css").read_text(encoding="utf-8")
HOST_UI = (ROOT / "server" / "settings_app.py").read_text(encoding="utf-8")

required_css = (
    "#connectView.connect", "#chatView .messages", "#chatView .rail",
    "#chatView .rooms", "overflow-y: auto;", "-webkit-overflow-scrolling: touch;",
    "touch-action: pan-y;", ".messages > * {", "flex-shrink: 0;",
    "#chatView .rail > :not(.rooms):not(.saved-host-list)",
    "#chatView .rail .rooms", "#chatView .rail .saved-host-list",
    "max-height: clamp(", "overscroll-behavior-y: auto;",
    "#chatView .stage {", "flex: 1 1 0px;", "height: 0;",
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
# Confirm the final round-4 overrides exist after earlier legacy rules.
assert CSS.rfind("#chatView .rail {") > CSS.find(".rail {")
assert CSS.rfind("#chatView .messages {") > CSS.find(".messages {")
assert CSS.rfind("#chatView .stage {") > CSS.find(".stage {")
print("UI scroll regression checks passed.")
