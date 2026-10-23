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
import threading
import tkinter as tk
import urllib.request
import ipaddress
from pathlib import Path
from tkinter import messagebox, ttk

FROZEN = bool(getattr(sys, "frozen", False))
HERE = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
HOST = HERE / "host.py"
HOST_EXE = HERE / "TerminusSecretsHost.exe"
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
# Planning assumptions for a host plus native/browser clients. These are not measured values.
BASE_HOST_MB = 220
CLIENT_MB = 180
MEDIA_SESSION_MB = {
    "photos": 18,
    "voice_messages": 30,
    "voice_calls": 90,
    "video_calls": 240,
    "screen_sharing": 140,
}
RAM_BUDGET_MB = 5 * 1024
RAM_CAUTION_MB = 4 * 1024


class HostSettingsApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Terminus Secrets · Host Manager")
        self.root.geometry("740x760")
        self.root.minsize(620, 680)
        self.root.configure(bg="#080d13")
        self.process: subprocess.Popen | None = None
        self.log_handle = None
        DATA.mkdir(parents=True, exist_ok=True)

        self.port = tk.StringVar(value="8443")
        self.public_url = tk.StringVar(value="")
        self.public_ipv6 = tk.StringVar(value="Checking…")
        self.client_address = tk.StringVar(value="Address unavailable")
        self.expected_clients = tk.IntVar(value=2)
        self.concurrent_media = tk.IntVar(value=1)
        self.status = tk.StringVar(value="Ready to configure")
        self.credentials = tk.StringVar(value="Not started yet — start the server to load its saved credentials.")
        self.vault_phrase = ""
        self.pairing_code = ""
        self.master_key = ""
        self.vault_phrase_var = tk.StringVar(value="Not loaded yet")
        self.pairing_code_var = tk.StringVar(value="Not loaded yet")
        self.master_key_var = tk.StringVar(value="Not loaded yet")
        self.vars = {name: tk.BooleanVar(value=DEFAULTS[name]) for name in DEFAULTS}
        self._load_config()
        self._style()
        self._build()
        self._update_estimate()
        self._refresh_ipv6()
        self.port.trace_add("write", lambda *_: self._update_address())
        self.public_url.trace_add("write", lambda *_: self._update_address())
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
                self.expected_clients.set(max(1, min(32, int(saved.get("expected_clients", 2)))))
                self.concurrent_media.set(max(0, min(12, int(saved.get("concurrent_media", 1)))))
        except (OSError, json.JSONDecodeError, AttributeError, TypeError):
            messagebox.showwarning("Settings reset", "The saved settings could not be read. Defaults will be used.")

    def _build(self) -> None:
        shell = ttk.Frame(self.root)
        shell.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(shell, bg="#080d13", highlightthickness=0, takefocus=True, yscrollincrement=24)
        self.scrollbar = ttk.Scrollbar(shell, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        outer = ttk.Frame(self.canvas, padding=24)
        self._content_window = self.canvas.create_window((0, 0), window=outer, anchor="nw")
        outer.bind("<Configure>", self._update_scroll_region)
        self.root.after_idle(self._update_scroll_region)
        self.canvas.bind("<Configure>", self._resize_scroll_content)
        # The canvas is keyboard-scrollable as well as mouse-wheel/touchpad scrollable.
        self.canvas.bind("<Prior>", lambda _event: self.canvas.yview_scroll(-1, "pages"))
        self.canvas.bind("<Next>", lambda _event: self.canvas.yview_scroll(1, "pages"))
        self.canvas.bind("<Home>", lambda _event: self.canvas.yview_moveto(0))
        self.canvas.bind("<End>", lambda _event: self.canvas.yview_moveto(1))
        self.canvas.bind("<Button-1>", lambda _event: self.canvas.focus_set(), add="+")
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
        ttk.Label(network, text="PUBLIC IPv6 ADDRESS", style="Muted.TLabel").pack(anchor="w", pady=(12, 4))
        iprow = ttk.Frame(network, style="Panel.TFrame"); iprow.pack(fill="x")
        ttk.Entry(iprow, textvariable=self.public_ipv6, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(iprow, text="Copy IPv6", command=lambda: self._copy_public_text(self.public_ipv6.get())).pack(side="left", padx=6)
        ttk.Button(iprow, text="Refresh", command=self._refresh_ipv6).pack(side="left")
        ttk.Label(network, text="CLIENT ADDRESS", style="Muted.TLabel").pack(anchor="w", pady=(10, 4))
        arow = ttk.Frame(network, style="Panel.TFrame"); arow.pack(fill="x")
        ttk.Entry(arow, textvariable=self.client_address, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(arow, text="Copy address", command=lambda: self._copy_public_text(self.client_address.get())).pack(side="left", padx=6)
        ttk.Label(network, text="IPv6 is formatted with brackets in the URL. Your carrier/router must allow inbound IPv6; changing networks can change this address without changing saved credentials.", style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(8, 0))

        secrets_panel = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        secrets_panel.pack(fill="x", pady=(0, 12))
        ttk.Label(secrets_panel, text="PERSISTENT HOST CREDENTIALS").pack(anchor="w", pady=(0, 6))
        ttk.Label(secrets_panel, text="Copy these values into your other devices. The vault phrase decrypts history; the pairing code and master key enroll devices.", style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(0, 8))
        for label, variable in (
            ("Vault phrase", self.vault_phrase_var),
            ("Pairing code", self.pairing_code_var),
            ("Master key", self.master_key_var),
        ):
            credential_row = ttk.Frame(secrets_panel, style="Panel.TFrame")
            credential_row.pack(fill="x", pady=4)
            ttk.Label(credential_row, text=label, width=13).pack(side="left", anchor="w")
            credential_entry = ttk.Entry(credential_row, textvariable=variable, state="readonly")
            credential_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
            ttk.Button(credential_row, text="Copy",
                command=lambda var=variable, title=label: self._copy_secret(var.get(), title)
            ).pack(side="right")
        ttk.Label(secrets_panel, text="Keep these values private. They remain in this host's data folder; only share them with people you trust.", style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(7, 0))

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
        ttk.Label(header, text="PROJECTED RAM · HOST + CLIENTS + ACTIVE MEDIA").pack(side="left")
        self.ram_text = ttk.Label(header, text="Calculating…", style="TLabel")
        self.ram_text.pack(side="right")
        capacity = ttk.Frame(estimate, style="Panel.TFrame")
        capacity.pack(fill="x", pady=(10, 2))
        ttk.Label(capacity, text="Local clients on this PC").pack(side="left")
        self.clients_spin = ttk.Spinbox(capacity, from_=1, to=32, width=5, textvariable=self.expected_clients, command=self._update_estimate)
        self.clients_spin.pack(side="left", padx=(8, 18))
        ttk.Label(capacity, text="Media sessions on this PC").pack(side="left")
        self.media_spin = ttk.Spinbox(capacity, from_=0, to=12, width=5, textvariable=self.concurrent_media, command=self._update_estimate)
        self.media_spin.pack(side="left", padx=(8, 0))
        self.expected_clients.trace_add("write", lambda *_: self._update_estimate())
        self.concurrent_media.trace_add("write", lambda *_: self._update_estimate())
        self.ram_bar = ttk.Progressbar(estimate, maximum=RAM_BUDGET_MB, mode="determinate")
        self.ram_bar.pack(fill="x", pady=(10, 7))
        ttk.Label(estimate, text="Scale: 0–5 GB available budget · orange warning above 4 GB", style="Muted.TLabel").pack(anchor="w")
        self.ram_note = ttk.Label(estimate, text="", style="Muted.TLabel", wraplength=620)
        self.ram_note.pack(anchor="w")
        self.cpu_text = ttk.Label(estimate, text="", style="TLabel", wraplength=620)
        self.cpu_text.pack(anchor="w", pady=(8, 0))
        self.vram_text = ttk.Label(estimate, text="", style="TLabel", wraplength=620)
        self.vram_text.pack(anchor="w", pady=(4, 0))

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(4, 0))
        ttk.Label(footer, textvariable=self.status, style="Muted.TLabel").pack(side="left", fill="x", expand=True)
        self.start_button = ttk.Button(footer, text="Start server", style="Start.TButton", command=self.start_server)
        self.start_button.pack(side="right")
        self.stop_button = ttk.Button(footer, text="Stop server", command=self.stop_server, state="disabled")
        self.stop_button.pack(side="right", padx=(0, 8))
        ttk.Label(outer, text=f"Settings: {CONFIG}", style="Muted.TLabel", wraplength=650).pack(anchor="w", pady=(14, 0))
        self._bind_scroll_events(outer)
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.root.bind_all(sequence, self._on_mousewheel, add="+")

    def _update_scroll_region(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_scroll_content(self, event) -> None:
        self.canvas.itemconfigure(self._content_window, width=event.width)

    def _on_mousewheel(self, event):
        number = getattr(event, "num", None)
        if number == 4:
            units = -3
        elif number == 5:
            units = 3
        else:
            delta = getattr(event, "delta", 0)
            if not delta:
                return "break"
            steps = max(1, int(abs(delta) / 120))
            units = -3 * steps if delta > 0 else 3 * steps
        self.canvas.yview_scroll(units, "units")
        return "break"

    def _bind_scroll_events(self, widget) -> None:
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            widget.bind(sequence, self._on_mousewheel, add="+")
        for child in widget.winfo_children():
            self._bind_scroll_events(child)

    def _copy_to_clipboard(self, value: str, label: str) -> bool:
        value = (value or "").strip()
        if not value:
            messagebox.showwarning("Unavailable", f"There is no {label.lower()} to copy yet.")
            return False
        # On Windows, clip.exe uses the OS clipboard directly and is more reliable
        # than Tk's ownership-based clipboard in packaged/frozen windows.
        try:
            if os.name == "nt":
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                result = subprocess.run(
                    ["clip.exe"], input=value, text=True, encoding="utf-8",
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    timeout=3, creationflags=flags, check=False,
                )
                if result.returncode == 0:
                    self.status.set(f"{label} copied to clipboard")
                    return True
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.root.update_idletasks()
            self.root.update()
            self.status.set(f"{label} copied to clipboard")
            return True
        except tk.TclError as exc:
            messagebox.showerror("Copy failed", f"Could not copy {label.lower()} to the clipboard: {exc}")
            self.status.set(f"Copy failed: {label}")
            return False

    def _copy_public_text(self, value: str) -> None:
        value = (value or "").strip()
        if not value or value in {"Checking…", "Address unavailable", "IPv6 unavailable"}:
            messagebox.showwarning("Unavailable", "There is no address to copy yet.")
            return
        self._copy_to_clipboard(value, "Address")

    def _copy_secret(self, value: str, label: str) -> None:
        value = (value or "").strip()
        if not value or value == "Not loaded yet":
            messagebox.showwarning("Credential unavailable", f"{label} is not available yet. Start the server first.")
            return
        self._copy_to_clipboard(value, label)

    def _update_address(self) -> None:
        custom = self.public_url.get().strip().rstrip("/")
        if custom:
            self.client_address.set(custom); return
        try:
            port = int(self.port.get().strip())
            if not 1 <= port <= 65535: raise ValueError
            ip = ipaddress.IPv6Address(self.public_ipv6.get().strip())
            self.client_address.set(f"https://[{ip.compressed}]:{port}")
        except (ValueError, ipaddress.AddressValueError, tk.TclError):
            self.client_address.set("IPv6 unavailable — set Public URL or refresh")

    def _refresh_ipv6(self) -> None:
        self.public_ipv6.set("Checking…"); self._update_address()
        def worker() -> None:
            result = ""
            for url in ("https://api6.ipify.org", "https://api64.ipify.org"):
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "TerminusSecretsHostManager/1.0"})
                    with urllib.request.urlopen(req, timeout=5) as response:
                        candidate = response.read(128).decode("ascii", "ignore").strip()
                    parsed = ipaddress.ip_address(candidate)
                    if isinstance(parsed, ipaddress.IPv6Address) and not parsed.is_private and not parsed.is_loopback:
                        result = parsed.compressed; break
                except (OSError, ValueError):
                    pass
            self.root.after(0, lambda: self._set_ipv6(result))
        threading.Thread(target=worker, daemon=True).start()

    def _set_ipv6(self, value: str) -> None:
        self.public_ipv6.set(value or "IPv6 unavailable")
        self._update_address()
        self.status.set("IPv6 detected; verify inbound firewall access" if value else "Could not detect public IPv6")

    def _estimate_mb(self) -> int:
        # Estimate scales with configured clients and concurrent active media.
        # Enabling a capability does not consume its full allowance while idle.
        try:
            clients = max(1, min(32, int(self.expected_clients.get())))
        except (tk.TclError, ValueError):
            clients = 2
        try:
            sessions = max(0, min(12, int(self.concurrent_media.get())))
        except (tk.TclError, ValueError):
            sessions = 1
        per_session = sum(MEDIA_SESSION_MB[key] for key, var in self.vars.items() if var.get())
        return BASE_HOST_MB + clients * CLIENT_MB + sessions * per_session

    def _update_estimate(self) -> None:
        if not hasattr(self, "ram_text"):
            return
        mb = self._estimate_mb()
        self.ram_text.configure(text=f"~{mb} MB ({mb / 1024:.2f} GB) / 5 GB system RAM")
        self.ram_bar.configure(value=min(mb, RAM_BUDGET_MB))
        try:
            local_clients = max(1, min(32, int(self.expected_clients.get())))
        except (tk.TclError, ValueError):
            local_clients = 2
        try:
            sessions = max(0, min(12, int(self.concurrent_media.get())))
        except (tk.TclError, ValueError):
            sessions = 1
        cpu_low = 1.0 + local_clients * 0.5
        cpu_high = 3.0 + local_clients * 1.2
        if self.vars["voice_calls"].get():
            cpu_low += sessions * 1.0
            cpu_high += sessions * 3.0
        if self.vars["video_calls"].get():
            cpu_low += sessions * 3.0
            cpu_high += sessions * 9.0
        if self.vars["screen_sharing"].get():
            cpu_low += sessions * 2.0
            cpu_high += sessions * 6.0
        self.cpu_text.configure(
            text=f"Estimated CPU on 12th-gen Intel Core i5: {min(100, cpu_low):.0f}–{min(100, cpu_high):.0f}%"
        )
        # The host is a signaling/message relay and does not transcode media.
        # VRAM applies only when this PC also runs a local Windows chat client.
        vram_low = sessions * (0.10 if self.vars["video_calls"].get() else 0.0)
        vram_high = sessions * (
            (0.45 if self.vars["video_calls"].get() else 0.0)
            + (0.20 if self.vars["screen_sharing"].get() else 0.0)
        )
        self.vram_text.configure(
            text=(f"Estimated RTX 3050 4 GB VRAM (local client only): "
                  f"{vram_low:.1f}–{min(3.8, vram_high):.1f} GB; host-only use is near 0 GB")
        )
        if mb > RAM_CAUTION_MB:
            note = ("WARNING: this planning estimate exceeds 4 GB. Reduce expected clients or concurrent media sessions. "
                    "This is a planning model, not a hard memory cap or live measurement.")
        else:
            note = ("Planning estimate only — not live telemetry, a benchmark, or a hard memory limit. It estimates this PC's "
                    "host plus local client(s); remote users' devices do not consume their full RAM on this host. Media costs "
                    "apply only to sessions active on this PC. Real usage depends on browser/WebView processes, resolution, "
                    "drivers, hardware acceleration, OS overhead, and other running apps.")
        self.ram_note.configure(text=note)

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
        try:
            expected_clients = max(1, min(32, int(self.expected_clients.get())))
            concurrent_media = max(0, min(12, int(self.concurrent_media.get())))
        except (ValueError, tk.TclError) as exc:
            raise ValueError("Connected clients must be 1–32 and media sessions 0–12.") from exc
        payload = {
            "port": port,
            "public_url": public_url,
            "features": {key: bool(var.get()) for key, var in self.vars.items()},
            "expected_clients": expected_clients,
            "concurrent_media": concurrent_media,
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
        if HOST_EXE.is_file():
            # Packaged distribution: launch the host executable beside this manager.
            # Persistent data stays beside the manager, not in a temporary extraction directory.
            command = [
                str(HOST_EXE), "--port", str(config["port"]),
                "--config", str(CONFIG), "--data-dir", str(DATA),
            ]
        else:
            # Source checkout: use the current Python interpreter and host.py.
            command = [
                sys.executable, str(HOST), "--port", str(config["port"]),
                "--config", str(CONFIG), "--data-dir", str(DATA),
            ]
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
        self._credential_poll_attempts = 0
        self._load_credentials()
        self.root.after(350, self._report_start)

    def _report_start(self) -> None:
        if not self.process or self.process.poll() is not None:
            self.status.set("Server exited · open server/data/host-errors.log for details")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            return
        self._load_credentials()
        if self.vault_phrase and self.pairing_code and self.master_key:
            self.status.set("Server running · all three credentials are ready to copy.")
            return
        self._credential_poll_attempts = getattr(self, "_credential_poll_attempts", 0) + 1
        if self._credential_poll_attempts < 60:
            self.status.set("Server starting · waiting for vault phrase, pairing code, and master key…")
            self.root.after(500, self._report_start)
        else:
            self.status.set("Server is running, but credentials are missing. Check the configured data folder and host-errors.log.")

    def _load_credentials(self) -> None:
        # Each file is independent and credentials are refreshed while the host
        # starts; this handles slow startup and packaged managers using --data-dir.
        def read_secret(filename: str) -> str:
            try:
                value = (DATA / filename).read_text(encoding="utf-8").strip()
                return value if value else ""
            except (OSError, UnicodeError):
                return ""

        vault = read_secret("vault-passphrase.txt")
        pairing = read_secret("pairing-code.txt").upper()
        master = read_secret("master-key.txt")
        self.vault_phrase = vault
        self.pairing_code = pairing
        self.master_key = master
        self.vault_phrase_var.set(vault or "Waiting for host to create vault phrase…")
        self.pairing_code_var.set(pairing or "Waiting for host to create pairing code…")
        self.master_key_var.set(master or "Waiting for host to create master key…")
        if vault and pairing and master:
            self.credentials.set("All host credentials loaded. Use the matching Copy button.")
        else:
            missing = []
            if not vault: missing.append("vault phrase")
            if not pairing: missing.append("pairing code")
            if not master: missing.append("master key")
            self.credentials.set("Waiting for: " + ", ".join(missing) + ". Credentials are read from: " + str(DATA))

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
