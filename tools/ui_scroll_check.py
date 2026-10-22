"""Fast regression checks for scroll reachability in both Terminus UIs.

These source checks catch known layout regressions; they do not replace manual
mouse-wheel/touch testing on real Android WebView and desktop windows.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
settings = (ROOT / "server" / "settings_app.py").read_text(encoding="utf-8")
css = (ROOT / "server" / "web" / "styles.css").read_text(encoding="utf-8")

required_settings = (
    "self.canvas = tk.Canvas",
    "self.canvas.configure(yscrollcommand=self.scrollbar.set)",
    "self.canvas.create_window((0, 0), window=outer, anchor=\"nw\")",
    "self.canvas.yview_scroll(units, \"units\")",
    "self._bind_scroll_events(outer)",
)
required_css = (
    ".rail {",
    ".rooms {",
    ".messages {",
    "overflow-y: auto;",
    "-webkit-overflow-scrolling: touch;",
    ".messages > * {",
    "flex-shrink: 0;",
    "touch-action: pan-y;",
)
missing = [f"settings_app.py missing {token!r}" for token in required_settings if token not in settings]
missing += [f"styles.css missing {token!r}" for token in required_css if token not in css]
if missing:
    raise SystemExit("\n".join(missing))
print("UI scroll source checks passed (native host manager + shared chat UI).")
