"""Regression checks for scroll reachability in the shared chat UI and host manager.

These source-level checks guard the CSS and Tkinter scroll plumbing. They are
supplemental; real touch/mouse testing is still needed on Android and Windows.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "server" / "web" / "styles.css").read_text(encoding="utf-8")
HOST_UI = (ROOT / "server" / "settings_app.py").read_text(encoding="utf-8")

required_css = (
    ".connect {",
    ".rail {",
    ".msg .bubble {",
    ".room-btn.active {",
    ".composer textarea {",
    ".primary {",
    ".dialog-head {",
    ".field input:focus-visible",
    ".rooms {",
    ".messages {",
    ".dialog {",
    "overflow-y: auto;",
    "-webkit-overflow-scrolling: touch;",
    "touch-action: pan-y;",
    "#chatView .messages > * {",
    "flex: 0 0 auto;",
    "#chatView .stage {",
    "min-height: 0;",
    "overscroll-behavior-y: contain;",
)
required_host = (
    "self.canvas = tk.Canvas",
    "self.canvas.configure(yscrollcommand=self.scrollbar.set)",
    'self.canvas.create_window((0, 0), window=outer, anchor="nw")',
    'self.canvas.yview_scroll(units, "units")',
    "self._bind_scroll_events(outer)",
    'self.root.bind_all(sequence, self._on_mousewheel, add="+")',
)
missing = [f"styles.css missing {item!r}" for item in required_css if item not in CSS]
missing += [f"settings_app.py missing {item!r}" for item in required_host if item not in HOST_UI]
if missing:
    raise SystemExit("\\n".join(missing))

# The final explicit rules must occur after the original layout rules.
assert CSS.rfind("#chatView .messages {") > CSS.find(".messages {")
assert CSS.rfind("#chatView .stage {") > CSS.find(".stage {")
print("UI scroll regression checks passed.")
