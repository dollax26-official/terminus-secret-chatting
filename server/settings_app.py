#!/usr/bin/env python3
"""Terminus Secrets host settings app.

Run with: python settings_app.py
Uses only the Python standard library. Settings are saved beside the host data;
the host's vault phrase, pairing code, certificate, and database remain stable.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

HERE = Path(__file__).resolve().parent
HOST = HERE / "host.py"
DATA = HERE / "data"
CONFIG = DATA / "server-settings.json"
LOG = DATA / "host-errors.log"

DEFAULTS = {
    "photos": True,
    "voice_messages": True,
    "voice_calls": True,
    "video_calls": True,
    "screen_sharing": True,
}
COST_MB = {
    "photos": 18,
    "voice_messages": 24,
    "voice_calls": 65,
    "video_calls": 150,
    "screen_sharing": 95,
}


class HostSettingsApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Terminus Secrets · Host Manager")
        self.root.geometry("720x680")
        self.root.minsize(600, 600)
        self.root.configure(bg="#080d13")
        self.process: subprocess.Popen | None = None
        self.log_handle = None
        DATA.mkdir(parents=True, exist_ok=True)

        self.port = tk.StringVar(value="8443")
        self.public_url = tk.StringVar(value="")
        self.status = tk.StringVar(value="Ready to configure")
        self.credentials = tk.StringVar(value="Not started yet — start the server to load its saved credentials.")
        self.vault_phrase = ""
        self.pairing_code = ""
        self.vars = {name: tk.BooleanVar(value=DEFAULTS[name]) for name in DEFAULTS}
        self._load_config()
        self._style()
        self._build()
        self._update_estimate()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(600, self._watch_process)

    def _style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#080d13")
        style.configure("Panel.TFrame", background="#101823")
        style.configure("TLabel", background="#080d13", foreground="#e8eef7", font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background="#080d13", foreground="#8fa0b5", font=("Segoe UI", 9))
        style.configure("Title.TLabel", background="#080d13", foreground="#e8eef7", font=("Segoe UI Semibold", 20))
        style.configure("TCheckbutton", background="#101823", foreground="#e8eef7", padding=8)
        style.map("TCheckbutton", background=[("active", "#101823")], foreground=[("active", "#3ee0c5")])
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(14, 9))
        style.configure("Start.TButton", background="#3ee0c5", foreground="#04211d")
        style.map("Start.TButton", background=[("active", "#70f0db")])
        style.configure("TEntry", fieldbackground="#080d13", foreground="#e8eef7", insertcolor="#e8eef7")
        style.configure("Horizontal.TProgressbar", troughcolor="#1c2735", background="#3ee0c5")

    def _load_config(self) -> None:
        if not CONFIG.exists():
            return
        try:
            saved = json.loads(CONFIG.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                for key in DEFAULTS:
                    self.vars[key].set(bool(saved.get("features", {}).get(key, True)))
                self.port.set(str(saved.get("port", 8443)))
                self.public_url.set(str(saved.get("public_url", "")))
        except (OSError, json.JSONDecodeError, AttributeError, TypeError):
            messagebox.showwarning("Settings reset", "The saved settings could not be read. Defaults will be used.")

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=24)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="TERMINUS  /  HOST MANAGER", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Configure your private server", style="Title.TLabel").pack(anchor="w", pady=(5, 3))
        ttk.Label(outer, text="Choose the capabilities clients can see. Your vault phrase and pairing code are kept in the data folder.", wraplength=640, style="Muted.TLabel").pack(anchor="w", pady=(0, 18))

        network = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        network.pack(fill="x", pady=(0, 12))
        ttk.Label(network, text="NETWORK SETTINGS").pack(anchor="w", pady=(0, 8))
        row = ttk.Frame(network, style="Panel.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="HTTPS port").pack(side="left")
        ttk.Entry(row, textvariable=self.port, width=9).pack(side="left", padx=(10, 20))
        ttk.Label(row, text="Public URL (optional)", style="TLabel").pack(side="left")
        ttk.Entry(row, textvariable=self.public_url).pack(side="left", fill="x", expand=True, padx=(10, 0))
        ttk.Label(network, text="An address change does not rotate your secrets. Remote clients still need a reachable IPv6 address or hostname.", style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(8, 0))

        secrets_panel = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        secrets_panel.pack(fill="x", pady=(0, 12))
        ttk.Label(secrets_panel, text="PERSISTENT HOST CREDENTIALS").pack(anchor="w", pady=(0, 6))
        ttk.Label(secrets_panel, textvariable=self.credentials, style="Muted.TLabel", wraplength=620).pack(anchor="w")
        ttk.Label(secrets_panel, text="Keep these values private. They stay on this host and are not sent to clients until you share them.", style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(5, 0))

        options = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        options.pack(fill="x", pady=(0, 12))
        ttk.Label(options, text="SERVER CAPABILITIES").pack(anchor="w", pady=(0, 7))
        labels = [
            ("photos", "Photo and file attachments"),
            ("voice_messages", "Recorded voice messages"),
            ("voice_calls", "One-to-one voice calls"),
            ("video_calls", "One-to-one video calls"),
            ("screen_sharing", "Screen sharing (where supported)"),
        ]
        for key, label in labels:
            ttk.Checkbutton(options, text=label, variable=self.vars[key], command=self._update_estimate).pack(anchor="w", fill="x")

        estimate = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        estimate.pack(fill="x", pady=(0, 12))
        header = ttk.Frame(estimate, style="Panel.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="ESTIMATED RAM · HOST + ONE ACTIVE CLIENT").pack(side="left")
        self.ram_text = ttk.Label(header, text="~350 MB", style="TLabel")
        self.ram_text.pack(side="right")
        self.ram_bar = ttk.Progressbar(estimate, maximum=1024, mode="determinate")
        self.ram_bar.pack(fill="x", pady=(10, 7))
        self.ram_note = ttk.Label(estimate, text="", style="Muted.TLabel", wraplength=620)
        self.ram_note.pack(anchor="w")

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(4, 0))
        ttk.Label(footer, textvariable=self.status, style="Muted.TLabel").pack(side="left", fill="x", expand=True)
        self.start_button = ttk.Button(footer, text="Start server", style="Start.TButton", command=self.start_server)
        self.start_button.pack(side="right")
        self.stop_button = ttk.Button(footer, text="Stop server", command=self.stop_server, state="disabled")
        self.stop_button.pack(side="right", padx=(0, 8))
        ttk.Label(outer, text=f"Settings: {CONFIG}", style="Muted.TLabel", wraplength=650).pack(anchor="w", pady=(14, 0))

    def _estimate_mb(self) -> int:
        # Planning estimate, not a measurement: Python/SQLite host baseline,
        # one browser/Electron/WebView client, plus enabled media/attachment paths.
        return 240 + sum(COST_MB[key] for key, var in self.vars.items() if var.get())

    def _update_estimate(self) -> None:
        mb = self._estimate_mb()
        self.ram_text.configure(text=f"~{mb} MB  ({mb / 1024:.2f} GB)")
        self.ram_bar.configure(value=min(mb, 1024))
        self.ram_note.configure(
            text="Approximate planning range only, not a live measurement. The host relays encrypted chat and call signaling; WebRTC media is peer-to-peer when networks permit it. Actual memory depends on the number of clients, browser/WebView, photos, and active media."
        )

    def _save(self) -> None:
        try:
            port = int(self.port.get().strip())
        except ValueError as exc:
            raise ValueError("HTTPS port must be a number between 1 and 65535.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("HTTPS port must be between 1 and 65535.")
        public_url = self.public_url.get().strip().rstrip("/")
        if public_url and not public_url.startswith("https://"):
            raise ValueError("Public URL must start with https://.")
        payload = {
            "port": port,
            "public_url": public_url,
            "features": {key: bool(var.get()) for key, var in self.vars.items()},
        }
        DATA.mkdir(parents=True, exist_ok=True)
        temp = CONFIG.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(temp, CONFIG)
        return payload

    def start_server(self) -> None:
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Already running", "The host server is already running.")
            return
        try:
            config = self._save()
        except ValueError as exc:
            messagebox.showerror("Check settings", str(exc))
            return
        command = [sys.executable, str(HOST), "--port", str(config["port"]), "--config", str(CONFIG)]
        if config["public_url"]:
            command.extend(["--public-url", config["public_url"]])
        try:
            # Host stdout includes the vault phrase and pairing code. Never persist
            # those secrets in a log file; only diagnostic stderr is recorded.
            self.log_handle = LOG.open("a", encoding="utf-8")
            self.process = subprocess.Popen(
                command,
                cwd=str(HERE),
                stdout=subprocess.DEVNULL,
                stderr=self.log_handle,
                stdin=subprocess.DEVNULL,
            )
        except OSError as exc:
            messagebox.showerror("Could not start host", str(exc))
            self.status.set("Start failed")
            return
        self.status.set(f"Starting host on HTTPS port {config['port']}…")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.root.after(1200, self._report_start)

    def _report_start(self) -> None:
        if self.process and self.process.poll() is None:
            self._load_credentials()
            self.status.set("Server process running · credentials shown above · diagnostics in host-errors.log")
        else:
            self.status.set("Server exited · open server/data/host-errors.log for details")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")

    def _load_credentials(self) -> None:
        try:
            vault = (DATA / "vault-passphrase.txt").read_text(encoding="utf-8").strip()
            pairing = (DATA / "pairing-code.txt").read_text(encoding="utf-8").strip()
            self.vault_phrase = vault
            self.pairing_code = pairing
            self.credentials.set(f"Vault phrase: {vault}\nPairing code: {pairing}")
        except OSError:
            self.credentials.set("Credentials are being initialized. Wait a moment, then check again.")

    def stop_server(self) -> None:
        if not self.process or self.process.poll() is not None:
            self.status.set("Server is stopped")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.status.set("Server stopped")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        if self.log_handle:
            self.log_handle.close()
            self.log_handle = None

    def _watch_process(self) -> None:
        if self.process and self.process.poll() is not None:
            self.status.set("Server stopped or exited · see host-errors.log")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            if self.log_handle:
                self.log_handle.close()
                self.log_handle = None
        self.root.after(600, self._watch_process)

    def _close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno("Stop server?", "The host is running. Stop it before closing the manager?"):
                return
            self.stop_server()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    HostSettingsApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
