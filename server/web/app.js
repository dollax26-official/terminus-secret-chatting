/* Terminus Secrets — client logic
   Crypto: PBKDF2-HMAC-SHA256 (600k) -> AES-256-GCM, all in the browser.
   The host only ever receives base64 ciphertext. */

(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const LS = {
    token: "ts.token",
    accountToken: "ts.account-token",
    account: "ts.account",
    device: "ts.device",
    name: "ts.name",
    room: "ts.room",
  };
  const VAULT_MARKER = "terminus-vault-v1";
  const AAD_PREFIX = "terminus-secrets:v1:";
  const CHECK_AAD = "terminus-secrets:vault-check:v1";

  const state = {
    mode: "pair",
    accountToken: localStorage.getItem(LS.accountToken) || "",
    account: (() => { try { return JSON.parse(localStorage.getItem(LS.account) || "null"); } catch (_) { return null; } })(),
    accountMode: "login",
    token: localStorage.getItem(LS.token) || "",
    deviceId: localStorage.getItem(LS.device) || "",
    deviceName: localStorage.getItem(LS.name) || guessDeviceName(),
    server: null,
    salt: null,
    iterations: 600000,
    key: null,
    rooms: [],
    servers: [],
    serverMembers: [],
    activeServerId: localStorage.getItem("ts.server") || "",
    searchQuery: "",
    devices: [],
    messages: [],
    messageIds: new Set(),
    lastId: 0,
    syncSince: "",
    replyTo: null,
    currentRoom: localStorage.getItem(LS.room) || "general",
    unread: new Map(),
    lastRendered: { day: null, device: null, at: 0 },
    polling: false,
    online: false,
    stopped: false,
    toastTimer: null,
    typingTimer: null,
    typingLastSent: 0,
    connecting: false,
    authMethod: "code",
    roomSignature: "",
    newBelow: 0,
    call: null,
    callSignalCursor: {},
    callSignalBusy: false,
    callSignalTimer: null,
    voiceRecorder: null,
    voiceChunks: [],
    voiceStopTimer: null,
    savedHosts: [],
  };

  const ui = {};

  /* ------------------------------------------------------------- utilities */
  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function uid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function guessDeviceName() {
    const ua = navigator.userAgent;
    if (/Android/i.test(ua)) return "Android device";
    if (/iPhone|iPad|iPod/i.test(ua)) return "iPhone";
    if (/Windows/i.test(ua)) return "Windows device";
    if (/Macintosh/i.test(ua)) return "Mac";
    if (/Linux/i.test(ua)) return "Linux device";
    return "New device";
  }

  function initials(name) {
    const cleaned = (name || "?").trim();
    return cleaned ? cleaned[0].toUpperCase() : "?";
  }

  function hueFor(id) {
    let hash = 0;
    for (let i = 0; i < (id || "").length; i += 1) {
      hash = (hash * 31 + id.charCodeAt(i)) % 360;
    }
    return hash;
  }

  function dayKey(iso) {
    const d = new Date(iso);
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  }

  function dayLabel(iso) {
    const d = new Date(iso);
    const today = new Date();
    const yesterday = new Date();
    yesterday.setDate(today.getDate() - 1);
    if (dayKey(iso) === dayKey(today.toISOString())) return "Today";
    if (dayKey(iso) === dayKey(yesterday.toISOString())) return "Yesterday";
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  }

  function clock(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  function seenLabel(iso) {
    if (!iso) return "never";
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 90) return "online now";
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  }

  function toast(message, kind = "") {
    ui.toast.textContent = message;
    ui.toast.className = `toast show ${kind}`.trim();
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      ui.toast.className = "toast";
    }, 3800);
  }

  function authHeaders(extra = {}) {
    const headers = { ...extra };
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    if (state.accountToken) headers["X-Account-Token"] = state.accountToken;
    return headers;
  }

  function api(path, options = {}) {
    return fetch(path, {
      cache: "no-store",
      ...options,
      headers: authHeaders(options.headers || {}),
    });
  }

  /* ---------------------------------------------------------------- crypto */
  async function deriveKey(passphrase, saltB64, iterations) {
    const base = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: b64ToBytes(saltB64),
        iterations,
        hash: "SHA-256",
      },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function aad(roomId) {
    return enc.encode(AAD_PREFIX + roomId);
  }

  async function encryptText(text, roomId) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = enc.encode(JSON.stringify({ t: "text", b: text }));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad(roomId) },
      state.key,
      payload
    );
    return {
      nonce: bytesToB64(iv),
      ciphertext: bytesToB64(new Uint8Array(ct)),
    };
  }

  async function decryptMessage(row) {
    try {
      const payload = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: b64ToBytes(row.nonce),
          additionalData: aad(row.room_id),
        },
        state.key,
        b64ToBytes(row.ciphertext)
      );
      const parsed = JSON.parse(dec.decode(payload));
      return typeof parsed.b === "string" ? parsed.b : "";
    } catch (err) {
      return null;
    }
  }

  async function verifyVault(vault) {
    if (!vault.check) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: enc.encode(CHECK_AAD) },
        state.key,
        enc.encode(VAULT_MARKER)
      );
      await api("/api/vault/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nonce: bytesToB64(iv),
          ciphertext: bytesToB64(new Uint8Array(ct)),
        }),
      });
      return true;
    }
    try {
      const clear = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: b64ToBytes(vault.check.nonce),
          additionalData: enc.encode(CHECK_AAD),
        },
        state.key,
        b64ToBytes(vault.check.ciphertext)
      );
      return dec.decode(clear) === VAULT_MARKER;
    } catch (err) {
      return false;
    }
  }

  /* ------------------------------------------------------------------ boot */
  function cacheUi() {
    ui.connectView = $("#connectView");
    ui.chatView = $("#chatView");
    ui.connectForm = $("#connectForm");
    ui.connectTitle = $("#connectTitle");
    ui.connectLede = $("#connectLede");
    ui.connectBtn = $("#connectBtn");
    ui.connectBtnLabel = $("#connectBtn .btn-label");
    ui.connectSpinner = $("#connectBtn .spinner");
    ui.connectError = $("#connectError");
    ui.pairFields = $("#pairFields");
    ui.authSwitch = $("#authSwitch");
    ui.codeField = $("#codeField");
    ui.masterField = $("#masterField");
    ui.masterKeyInput = $("#masterKeyInput");
    ui.codeInput = $("#codeInput");
    ui.deviceInput = $("#deviceInput");
    ui.passInput = $("#passInput");
    ui.revealBtn = $("#revealBtn");
    ui.switchModeBtn = $("#switchModeBtn");
    ui.hostBadge = $("#hostBadge");
    ui.hostBadgeText = $("#hostBadgeText");
    ui.roomList = $("#roomList");
    ui.dmList = $("#dmList");
    ui.savedHostList = $("#savedHostList");
    ui.addHostBtn = $("#addHostBtn");
    ui.serverSelect = $("#serverSelect");
    ui.searchInput = $("#searchInput");
    ui.fileInput = $("#fileInput");
    ui.attachBtn = $("#attachBtn");
    ui.voiceMessageBtn = $("#voiceMessageBtn");
    ui.audioCallBtn = $("#audioCallBtn");
    ui.videoCallBtn = $("#videoCallBtn");
    ui.screenCallBtn = $("#screenCallBtn");
    ui.callPanel = $("#callPanel");
    ui.callTitle = $("#callTitle");
    ui.callStatus = $("#callStatus");
    ui.localCallVideo = $("#localCallVideo");
    ui.remoteCallVideo = $("#remoteCallVideo");
    ui.remoteCallAudio = $("#remoteCallAudio");
    ui.muteCallBtn = $("#muteCallBtn");
    ui.cameraCallBtn = $("#cameraCallBtn");
    ui.shareCallBtn = $("#shareCallBtn");
    ui.endCallBtn = $("#endCallBtn");
    ui.roomTitle = $("#roomTitle");
    ui.roomMeta = $("#roomMeta");
    ui.syncState = $("#syncState");
    ui.railLive = $("#railLive");
    ui.messages = $("#messages");
    ui.typingIndicator = $("#typingIndicator");
    ui.jumpBtn = $("#jumpBtn");
    ui.emptyState = $("#emptyState");
    ui.emptyTitle = $("#emptyTitle");
    ui.emptyText = $("#emptyText");
    ui.composer = $("#composer");
    ui.input = $("#input");
    ui.sendBtn = $("#sendBtn");
    ui.meName = $("#meName");
    ui.meMeta = $("#meMeta");
    ui.meAvatar = $("#meAvatar");
    ui.settingsBtn = $("#settingsBtn");
    ui.settingsDialog = $("#settingsDialog");
    ui.backgroundColorInput = $("#backgroundColorInput");
    ui.accentColorInput = $("#accentColorInput");
    ui.resetAppearanceBtn = $("#resetAppearanceBtn");
    ui.infoDialog = $("#infoDialog");
    ui.infoHost = $("#infoHost");
    ui.infoFingerprint = $("#infoFingerprint");
    ui.deviceList = $("#deviceList");
    ui.copyFingerprintBtn = $("#copyFingerprintBtn");
    ui.notifyBtn = $("#notifyBtn");
    ui.changeHostBtn = $("#changeHostBtn");
    ui.roomDialog = $("#roomDialog");
    ui.roomForm = $("#roomForm");
    ui.roomNameInput = $("#roomNameInput");
    ui.roomCategoryInput = $("#roomCategoryInput");
    ui.roomDescriptionInput = $("#roomDescriptionInput");
    ui.roomPrivateInput = $("#roomPrivateInput");
    ui.roomError = $("#roomError");
    ui.toast = $("#toast");
    ui.rail = $("#rail");
    ui.backdrop = $("#backdrop");
  }

  function toggleAccountMode() {
    state.accountMode = state.accountMode === "login" ? "register" : "login";
    ui.accountTitle.textContent = state.accountMode === "login" ? "Sign in to this server" : "Create your account";
    ui.accountBtn.textContent = state.accountMode === "login" ? "Sign in" : "Create account";
    ui.accountModeBtn.textContent = state.accountMode === "login" ? "Need an account? Create one" : "Already registered? Sign in";
    ui.accountPassword.autocomplete = state.accountMode === "login" ? "current-password" : "new-password";
    ui.accountError.textContent = "";
  }

  async function onAccountSubmit(event) {
    event.preventDefault();
    ui.accountError.textContent = "";
    const username = ui.accountUsername.value.trim();
    const password = ui.accountPassword.value;
    if (!username || !password) {
      ui.accountError.textContent = "Enter both your username and password.";
      return;
    }
    ui.accountBtn.disabled = true;
    try {
      const endpoint = state.accountMode === "register" ? "/api/accounts/register" : "/api/accounts/login";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Account authentication failed.");
      state.accountToken = data.account_token;
      state.account = data.account;
      localStorage.setItem(LS.accountToken, state.accountToken);
      localStorage.setItem(LS.account, JSON.stringify(state.account));
      ui.accountPanel.hidden = true;
      ui.connectForm.hidden = false;
      ui.accountPassword.value = "";
      if (state.token) setMode("unlock");
      else setMode("pair");
      toast(`Signed in as ${state.account.username}.`);
    } catch (err) {
      ui.accountError.textContent = err.message || "Account authentication failed.";
    } finally {
      ui.accountBtn.disabled = false;
    }
  }

  function applyAppearance() {
    const background = ui.backgroundColorInput.value || "#06090e";
    const accent = ui.accentColorInput.value || "#3ee0c5";
    document.documentElement.style.setProperty("--bg", background);
    document.documentElement.style.setProperty("--bg-2", background);
    document.documentElement.style.setProperty("--accent", accent);
    document.documentElement.style.setProperty("--accent-soft", accent + "20");
    document.documentElement.style.setProperty("--accent-line", accent + "55");
    try {
      localStorage.setItem("ts.appearance", JSON.stringify({ background, accent }));
    } catch (_) {}
  }

  function openSettings() {
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem("ts.appearance") || "{}"); } catch (_) {}
    ui.backgroundColorInput.value = saved.background || "#06090e";
    ui.accentColorInput.value = saved.accent || "#3ee0c5";
    applyAppearance();
    ui.settingsDialog.showModal();
  }

  function bindEvents() {
    ui.accountForm = $("#accountForm");
    ui.accountPanel = $("#accountPanel");
    ui.accountError = $("#accountError");
    ui.accountBtn = $("#accountBtn");
    ui.accountModeBtn = $("#accountModeBtn");
    ui.accountUsername = $("#accountUsername");
    ui.accountPassword = $("#accountPassword");
    ui.accountForm.addEventListener("submit", onAccountSubmit);
    ui.accountModeBtn.addEventListener("click", toggleAccountMode);
    ui.connectForm.addEventListener("submit", onConnect);
    ui.revealBtn.addEventListener("click", () => {
      const show = ui.passInput.type === "password";
      ui.passInput.type = show ? "text" : "password";
      ui.revealBtn.textContent = show ? "hide" : "show";
      ui.passInput.focus();
    });
    ui.switchModeBtn.addEventListener("click", () => {
      if (state.mode === "unlock") {
        setMode("pair");
      } else if (state.token) {
        setMode("unlock");
      }
    });
    ui.authSwitch.addEventListener("click", (event) => {
      const button = event.target.closest("[data-auth]");
      if (button) setAuthMethod(button.dataset.auth);
    });

    ui.composer.addEventListener("submit", (event) => {
      event.preventDefault();
      submitComposer();
    });
    ui.addHostBtn.addEventListener("click", addSavedHost);
    ui.serverSelect.addEventListener("change", () => {
      state.activeServerId = ui.serverSelect.value;
      localStorage.setItem("ts.server", state.activeServerId);
      const first = state.rooms.find((room) => room.kind !== "dm" && room.server_id === state.activeServerId);
      if (first) selectRoom(first.id); else renderRooms();
    });
    $("#createServerBtn").addEventListener("click", createServer);
    $("#joinServerBtn").addEventListener("click", joinServer);
    $("#inviteServerBtn").addEventListener("click", showServerInvite);
    $("#manageRolesBtn").addEventListener("click", manageServerRoles);
    $("#newDmBtn").addEventListener("click", openDirectMessage);
    ui.searchInput.addEventListener("input", () => {
      state.searchQuery = ui.searchInput.value.trim().toLocaleLowerCase();
      renderMessages();
    });
    ui.attachBtn.addEventListener("click", () => ui.fileInput.click());
    ui.fileInput.addEventListener("change", sendAttachment);
    ui.voiceMessageBtn.addEventListener("click", toggleVoiceRecording);
    ui.audioCallBtn.addEventListener("click", () => startCall("audio"));
    ui.videoCallBtn.addEventListener("click", () => startCall("video"));
    ui.screenCallBtn.addEventListener("click", toggleScreenShare);
    ui.muteCallBtn.addEventListener("click", toggleCallMute);
    ui.cameraCallBtn.addEventListener("click", toggleCallCamera);
    ui.shareCallBtn.addEventListener("click", toggleScreenShare);
    ui.endCallBtn.addEventListener("click", () => endCall(true));
    ui.input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        submitComposer();
      }
    });
    ui.input.addEventListener("input", () => {
      autoGrow();
      const typing = Boolean(ui.input.value.trim());
      if (typing) sendTyping(true);
      clearTimeout(state.typingTimer);
      if (typing) state.typingTimer = setTimeout(() => sendTyping(false), 2200);
      else sendTyping(false);
    });
    ui.messages.addEventListener("scroll", updateJump, { passive: true });
    ui.jumpBtn.addEventListener("click", () => scrollToBottom());

    ui.menuBtn = $("#menuBtn");
    ui.menuBtn.addEventListener("click", () => {
      ui.chatView.classList.add("rail-open");
    });
    ui.backdrop.addEventListener("click", () => {
      ui.chatView.classList.remove("rail-open");
    });

    $("#newRoomBtn").addEventListener("click", () => {
      ui.roomError.textContent = "";
      ui.roomNameInput.value = "";
      ui.roomCategoryInput.value = "";
      ui.roomDescriptionInput.value = "";
      ui.roomDialog.showModal();
      setTimeout(() => ui.roomNameInput.focus(), 40);
    });
    $("#infoBtn").addEventListener("click", openInfo);
    ui.settingsBtn.addEventListener("click", openSettings);
    ui.backgroundColorInput.addEventListener("input", applyAppearance);
    ui.accentColorInput.addEventListener("input", applyAppearance);
    ui.resetAppearanceBtn.addEventListener("click", () => {
      ui.backgroundColorInput.value = "#06090e";
      ui.accentColorInput.value = "#3ee0c5";
      applyAppearance();
    });
    $("#lockBtn").addEventListener("click", lockAndForget);
    ui.copyFingerprintBtn.addEventListener("click", copyFingerprint);
    ui.notifyBtn.addEventListener("click", enableNotifications);
    ui.changeHostBtn.addEventListener("click", () => {
      localStorage.removeItem(LS.token);
      localStorage.removeItem(LS.device);
      location.href = "/setup";
    });
    $("#switchAccountBtn").addEventListener("click", async () => {
      if (state.accountToken) {
        try {
          await fetch("/api/accounts/logout", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: "{}" });
        } catch (_) {}
      }
      state.accountToken = "";
      state.account = null;
      state.token = "";
      state.deviceId = "";
      state.key = null;
      localStorage.removeItem(LS.accountToken);
      localStorage.removeItem(LS.account);
      localStorage.removeItem(LS.token);
      localStorage.removeItem(LS.device);
      ui.chatView.hidden = true;
      ui.connectView.hidden = false;
      ui.accountPanel.hidden = false;
      ui.connectForm.hidden = true;
      state.accountMode = "login";
      toggleAccountMode();
      toggleAccountMode();
    });

    ui.roomForm.addEventListener("submit", createRoom);
    ui.roomDialog.querySelectorAll("[data-close]").forEach((button) => {
      button.addEventListener("click", () => ui.roomDialog.close());
    });
    ui.roomForm.querySelectorAll('button[value="cancel"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        ui.roomDialog.close();
      });
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && ui.chatView.classList.contains("rail-open")) {
        ui.chatView.classList.remove("rail-open");
      }
    });

    window.addEventListener("beforeunload", () => {
      state.stopped = true;
    });

    try {
      const savedAppearance = JSON.parse(localStorage.getItem("ts.appearance") || "{}");
      document.documentElement.style.setProperty("--bg", savedAppearance.background || "#06090e");
      document.documentElement.style.setProperty("--bg-2", savedAppearance.background || "#06090e");
      document.documentElement.style.setProperty("--accent", savedAppearance.accent || "#3ee0c5");
    } catch (_) {}

    if ("serviceWorker" in navigator && location.protocol === "https:") {
      navigator.serviceWorker.register("sw.js", { scope: "./" }).catch(() => {});
    }
  }

  function setAuthMethod(method) {
    state.authMethod = method === "master" ? "master" : "code";
    ui.codeField.hidden = state.authMethod !== "code";
    ui.masterField.hidden = state.authMethod !== "master";
    ui.authSwitch.querySelectorAll("[data-auth]").forEach((button) => {
      const active = button.dataset.auth === state.authMethod;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    ui.connectError.textContent = "";
    setTimeout(() => {
      (state.authMethod === "master" ? ui.masterKeyInput : ui.codeInput).focus();
    }, 40);
  }

  function setMode(mode) {
    state.mode = mode;
    const unlock = mode === "unlock";
    ui.pairFields.hidden = unlock;
    ui.connectTitle.textContent = unlock ? "Welcome back." : "Open your private channel.";
    ui.connectLede.textContent = unlock
      ? "This device is already paired. Enter the vault passphrase to decrypt your history."
      : "Pair this device with the host running on your laptop. Messages are encrypted here, before they ever touch the network.";
    ui.connectBtnLabel.textContent = unlock ? "Unlock channel" : "Pair this device";
    ui.switchModeBtn.hidden = !state.token;
    ui.switchModeBtn.textContent = unlock ? "Pair a different device" : "Back to unlock";
    ui.connectError.textContent = "";
    if (!unlock) {
      ui.codeInput.value = "";
      ui.deviceInput.value = state.deviceName || guessDeviceName();
      setAuthMethod(state.authMethod);
    }
    setTimeout(() => (unlock ? ui.passInput : ui.codeInput).focus(), 60);
  }

  async function checkHost() {
    try {
      const res = await fetch("/api/health", { cache: "no-store" });
      if (!res.ok) throw new Error("bad status");
      const health = await res.json();
      state.server = health;
      ui.hostBadge.classList.remove("offline");
      const fp = (health.fingerprint || "").split(":").slice(0, 3).join(":");
      ui.hostBadgeText.textContent = `${health.server_name} · ${fp}…`;
      return true;
    } catch (err) {
      ui.hostBadge.classList.add("offline");
      ui.hostBadgeText.textContent = "Host unreachable at this address";
      return false;
    }
  }

  async function onConnect(event) {
    event.preventDefault();
    if (state.connecting) return;
    ui.connectError.textContent = "";

    const passphrase = ui.passInput.value.trim();
    if (!passphrase) {
      ui.connectError.textContent = "Enter the vault passphrase.";
      ui.passInput.focus();
      return;
    }
    if (passphrase.length < 8) {
      ui.connectError.textContent = "The vault passphrase is at least 8 characters.";
      ui.passInput.focus();
      return;
    }

    if (!window.crypto || !crypto.subtle) {
      ui.connectError.textContent =
        "This browser can't run WebCrypto here. Open the host over HTTPS.";
      return;
    }

    state.connecting = true;
    ui.connectBtn.disabled = true;
    ui.connectSpinner.hidden = false;

    try {
      if (state.mode === "pair") {
        const name = ui.deviceInput.value.trim() || guessDeviceName();
        const payload = { device_name: name };
        if (state.authMethod === "master") {
          const masterKey = ui.masterKeyInput.value.trim();
          if (masterKey.length < 20) {
            throw new Error("Paste the master key printed by the host.");
          }
          payload.master_key = masterKey;
        } else {
          const code = ui.codeInput.value.trim().toUpperCase().replace(/\s+/g, "");
          if (code.replace("-", "").length < 6) {
            throw new Error("Enter the pairing code shown in the host window.");
          }
          payload.code = code;
        }
        const res = await fetch("/api/pair", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (res.status === 403) {
            throw new Error(
              state.authMethod === "master"
                ? "That master key is not valid for this host."
                : "That pairing code is wrong or expired."
            );
          }
          if (res.status === 429) throw new Error("Too many attempts. Wait a minute, then retry.");
          throw new Error(data.error || "Pairing failed.");
        }
        state.token = data.token;
        state.deviceId = data.device_id;
        state.deviceName = data.device_name || name;
        localStorage.setItem(LS.token, state.token);
        localStorage.setItem(LS.device, state.deviceId);
        localStorage.setItem(LS.name, state.deviceName);
      }

      const vault = await loadVault();
      ui.connectBtnLabel.textContent = "Deriving key…";
      state.key = await deriveKey(passphrase, vault.salt, vault.iterations);
      const ok = await verifyVault(vault);
      if (!ok) {
        state.key = null;
        throw new Error("That passphrase does not match this vault.");
      }

      await initialSync();
      enterChat();
    } catch (err) {
      if (err && err.name === "OperationError") {
        ui.connectError.textContent = "That passphrase does not match this vault.";
      } else {
        ui.connectError.textContent = err.message || "Could not connect.";
      }
      if (/unauthorized|no longer authorized/i.test(err.message || "")) {
        forgetToken();
      }
    } finally {
      state.connecting = false;
      ui.connectBtn.disabled = false;
      ui.connectSpinner.hidden = true;
      if (!ui.chatView.hidden) return;
      ui.connectBtnLabel.textContent =
        state.mode === "unlock" ? "Unlock channel" : "Pair this device";
    }
  }

  async function loadVault() {
    const res = await api("/api/vault");
    if (res.status === 401) {
      forgetToken();
      throw new Error("This device is no longer authorized. Pair it again.");
    }
    if (!res.ok) throw new Error("Could not read the vault settings.");
    const vault = await res.json();
    state.salt = vault.salt;
    state.iterations = vault.iterations;
    return vault;
  }

  async function initialSync() {
    let guard = 0;
    state.messages = [];
    state.lastId = 0;
    while (guard < 50) {
      guard += 1;
      const res = await api(`/api/sync?after=${state.lastId}&wait=0&updated_after=${encodeURIComponent(state.syncSince)}`);
      if (res.status === 401) {
        forgetToken();
        throw new Error("This device is no longer authorized. Pair it again.");
      }
      if (!res.ok) throw new Error("Could not load history from the host.");
      const data = await res.json();
      await applySync(data, { quiet: true });
      if (!data.has_more) break;
    }
  }

  /* ------------------------------------------------------------------- sync */
  async function applySync(data, options = {}) {
    state.rooms = data.rooms || state.rooms;
    state.servers = data.servers || state.servers;
    state.serverMembers = data.server_members || state.serverMembers;
    if (!state.activeServerId || !state.servers.some((server) => server.id === state.activeServerId)) {
      state.activeServerId = state.servers[0]?.id || "";
      if (state.activeServerId) localStorage.setItem("ts.server", state.activeServerId);
    }
    state.devices = data.devices || state.devices;
    const typingNames = Array.from(new Set((data.typing || []).filter((item) => item.room_id === state.currentRoom).map((item) => item.username)));
    ui.typingIndicator.hidden = typingNames.length === 0;
    ui.typingIndicator.textContent = typingNames.length ? `${typingNames.join(", ")} ${typingNames.length === 1 ? "is" : "are"} typing…` : "";
    state.lastId = data.last_id ?? state.lastId;
    state.syncSince = data.server_time || state.syncSince;
    if (data.you) state.deviceId = data.you;

    let changedExisting = false;
    const incoming = [];
    const decryptRows = [];
    for (const row of data.messages || []) {
      const messageKey = String(row.id);
      const existing = state.messages.find((m) => String(m.id) === messageKey);
      if (existing) {
        if (row.deleted) {
          existing.deleted = true;
          existing.text = "Message deleted";
          existing.failedDecrypt = false;
          existing.edited_at = row.edited_at || existing.edited_at;
          existing.pinned = Boolean(row.pinned);
          changedExisting = true;
          continue;
        }
        if (row.edited_at && row.edited_at !== existing.edited_at) {
          state.messages = state.messages.filter((m) => m !== existing);
          state.messageIds.delete(messageKey);
          changedExisting = true;
        } else {
          existing.pinned = Boolean(row.pinned);
          continue;
        }
      }
      if (row.deleted) {
        state.messageIds.add(messageKey);
        incoming.push({
          id: row.id, client_msg_id: row.client_msg_id, room_id: row.room_id,
          device_id: row.device_id, device_name: row.device_name || "Device",
          created_at: row.created_at, text: "Message deleted", deleted: true,
          edited_at: row.edited_at, pinned: Boolean(row.pinned), reply_to_id: row.reply_to_id,
        });
        continue;
      }
      state.messageIds.add(messageKey);

      // Only search for optimistic messages when this row belongs to us.
      // Avoid scanning the full local history for every other user's message.
      if (row.device_id === state.deviceId) {
        const local = state.messages.find(
          (m) => m.client_msg_id === row.client_msg_id && String(m.id).startsWith("tmp-")
        );
        if (local) {
          local.id = row.id;
          local.created_at = row.created_at;
          local.pending = false;
          local.failed = false;
          if (local.room_id === state.currentRoom) updateMessageNode(local);
          continue;
        }
      }
      decryptRows.push(row);
    }

    // WebCrypto can decrypt a batch concurrently; sequential awaits made large
    // history syncs visibly block message rendering on slower phones.
    const decryptedTexts = await Promise.all(decryptRows.map((row) => decryptMessage(row)));
    for (let i = 0; i < decryptRows.length; i += 1) {
      const row = decryptRows[i];
      const text = decryptedTexts[i];
      incoming.push({
        id: row.id,
        client_msg_id: row.client_msg_id,
        room_id: row.room_id,
        device_id: row.device_id,
        device_name: row.device_name || "Device",
        created_at: row.created_at,
        text: text === null ? "" : text,
        failedDecrypt: text === null,
        edited_at: row.edited_at || null,
        deleted: Boolean(row.deleted),
        pinned: Boolean(row.pinned),
        reply_to_id: row.reply_to_id ?? null,
        reactions: row.reactions || [],
      });
    }

    for (const message of incoming) {
      state.messages.push(message);
      if (message.room_id === state.currentRoom) {
        if (ui.chatView.hidden) continue;
        appendMessage(message, { updateEmpty: false });
      } else {
        state.unread.set(message.room_id, (state.unread.get(message.room_id) || 0) + 1);
      }
    }

    renderRooms();
    if (!ui.chatView.hidden) {
      updateHeader();
      if (changedExisting) renderMessages();
      else updateEmptyState();
    }

    const mention = incoming.find((message) => state.account?.username &&
      (message.text || "").toLowerCase().includes("@" + state.account.username.toLowerCase()) &&
      message.device_id !== state.deviceId);
    if (incoming.length && (document.hidden || (mention && mention.room_id !== state.currentRoom))) {
      notifyNew(mention || incoming[incoming.length - 1]);
    }
    updateTitle();
  }

  async function pollLoop() {
    if (state.polling) return;
    state.polling = true;
    while (!state.stopped) {
      try {
        const res = await api(`/api/sync?after=${state.lastId}&wait=20&updated_after=${encodeURIComponent(state.syncSince)}`);
        if (res.status === 401) {
          lockOut("This device was revoked by the host.");
          break;
        }
        if (!res.ok) throw new Error("sync failed");
        const data = await res.json();
        await applySync(data);
        setOnline(true);
      } catch (err) {
        if (state.stopped) break;
        setOnline(false);
        await sleep(1600 + Math.random() * 1600);
      }
    }
    state.polling = false;
  }

  function setOnline(online) {
    if (state.online === online) return;
    state.online = online;
    ui.syncState.textContent = online ? "live" : "reconnecting";
    ui.syncState.classList.toggle("warn", !online);
    ui.railLive.classList.toggle("off", !online);
  }

  function enterChat() {
    state.stopped = false;
    ui.connectView.hidden = true;
    ui.chatView.hidden = false;
    ui.passInput.value = "";
    ui.masterKeyInput.value = "";
    document.title = "Terminus Secrets";
    ui.meName.textContent = state.account?.username || state.deviceName || "This device";
    ui.meMeta.textContent = state.deviceName || "encrypted session";
    ui.meAvatar.textContent = initials(state.account?.username || state.deviceName);
    ui.meAvatar.style.setProperty("--hue", hueOf(state.deviceId));

    if (!state.rooms.some((r) => r.id === state.currentRoom)) {
      state.currentRoom = state.rooms[0]?.id || "general";
    }
    renderRooms();
    renderSavedHosts();
    updateHeader();
    renderMessages();
    setOnline(true);
    pollLoop();
    if (!state.callSignalTimer) state.callSignalTimer = setInterval(pollCallSignals, 1800);
    setTimeout(() => ui.input.focus(), 120);
  }

  function hueOf(id) {
    return hueFor(id) % 360;
  }

  /* ------------------------------------------------------------------- rooms */
  function renderRooms() {
    const signature = state.rooms.map((room) => `${room.id}:${room.name}:${room.description || ""}:${room.kind || "text"}`).join("|") +
      "|" + state.servers.map((server) => `${server.id}:${server.name}:${server.role}`).join("|") +
      `|${state.activeServerId}|${state.currentRoom}|` +
      Array.from(state.unread.entries()).map(([id, count]) => `${id}=${count}`).join(",");
    if (signature === state.roomSignature) return;
    state.roomSignature = signature;

    ui.serverSelect.replaceChildren();
    for (const server of state.servers) {
      const option = el("option", "", server.name);
      option.value = server.id;
      ui.serverSelect.append(option);
    }
    ui.serverSelect.disabled = state.servers.length === 0;
    if (state.activeServerId) ui.serverSelect.value = state.activeServerId;
    const channelFragment = document.createDocumentFragment();
    const dmFragment = document.createDocumentFragment();
    const channels = state.rooms.filter((room) => room.kind !== "dm" && room.server_id === state.activeServerId);
    const dms = state.rooms.filter((room) => room.kind === "dm");
    const groupedChannels = new Map();
    for (const room of channels) {
      const category = room.category || "";
      if (!groupedChannels.has(category)) groupedChannels.set(category, []);
      groupedChannels.get(category).push(room);
    }
    for (const [category, categoryRooms] of groupedChannels) {
      if (category) channelFragment.append(el("div", "channel-category", category.toUpperCase()));
      for (const room of categoryRooms) {
        const button = el("button", "room-btn" + (room.id === state.currentRoom ? " active" : ""));
        button.type = "button";
        button.append(el("span", "hash", "#"), el("span", "name", room.name));
        const unread = state.unread.get(room.id) || 0;
        if (unread > 0 && room.id !== state.currentRoom) button.append(el("span", "unread", unread > 99 ? "99+" : String(unread)));
        button.addEventListener("click", () => selectRoom(room.id));
        channelFragment.append(button);
        if (room.name !== "general" && ["owner", "admin"].includes(state.servers.find((server) => server.id === state.activeServerId)?.role)) {
          const manage = el("button", "room-manage", "···");
          manage.type = "button"; manage.title = `Manage #${room.name}`;
          manage.addEventListener("click", (event) => { event.stopPropagation(); manageRoom(room); });
          channelFragment.append(manage);
        }
      }
    }
    for (const room of dms) {
      const button = el("button", "room-btn" + (room.id === state.currentRoom ? " active" : ""));
      button.type = "button"; button.append(el("span", "hash", "@"), el("span", "name", room.name));
      const unread = state.unread.get(room.id) || 0;
      if (unread > 0 && room.id !== state.currentRoom) button.append(el("span", "unread", unread > 99 ? "99+" : String(unread)));
      button.addEventListener("click", () => selectRoom(room.id));
      dmFragment.append(button);
    }
    ui.roomList.replaceChildren(channelFragment);
    ui.dmList.replaceChildren(dmFragment);
    updateTitle();
  }

  function updateTitle() {
    const total = Array.from(state.unread.values()).reduce((sum, value) => sum + value, 0);
    document.title = total > 0 ? `(${total}) Terminus Secrets` : "Terminus Secrets";
  }

  function selectRoom(roomId) {
    sendTyping(false);
    if (state.currentRoom === roomId) {
      ui.chatView.classList.remove("rail-open");
      return;
    }
    state.currentRoom = roomId;
    localStorage.setItem(LS.room, roomId);
    state.unread.delete(roomId);
    state.newBelow = 0;
    ui.jumpBtn.hidden = true;
    state.lastRendered = { day: null, device: null, at: 0 };
    renderRooms();
    updateHeader();
    renderMessages();
    updateEmptyState();
    ui.chatView.classList.remove("rail-open");
    ui.input.focus();
  }

  function currentRoom() {
    return state.rooms.find((r) => r.id === state.currentRoom) || { name: "general" };
  }

  function updateHeader() {
    const room = currentRoom();
    const isDm = room.kind === "dm";
    const server = state.servers.find((item) => item.id === room.server_id);
    ui.roomTitle.textContent = `${isDm ? "@" : "#"} ${room.name || "general"}`;
    const count = state.devices.length || 1;
    const description = isDm ? "Direct message" : (server ? server.name : (room.description || "Server channel"));
    ui.roomMeta.textContent = `${description} · ${count} device${count === 1 ? "" : "s"} · end-to-end encrypted`;
    ui.input.placeholder = `Message ${isDm ? "@" : "#"}${room.name || "general"}`;
  }

  /* ---------------------------------------------------------------- messages */
  function renderMessages() {
    ui.messages.replaceChildren();
    state.lastRendered = { day: null, device: null, at: 0 };
    state.newBelow = 0;
    ui.jumpBtn.hidden = true;
    const list = state.messages.filter((m) => m.room_id === state.currentRoom &&
      (!state.searchQuery || (m.text || "").toLocaleLowerCase().includes(state.searchQuery)));
    for (const message of list) appendMessage(message, { forceScroll: false, track: false, updateEmpty: false });
    updateEmptyState();
    scrollToBottom(false);
  }

  function updateEmptyState() {
    const list = state.messages.filter((m) => m.room_id === state.currentRoom &&
      (!state.searchQuery || (m.text || "").toLocaleLowerCase().includes(state.searchQuery)));
    const empty = list.length === 0;
    ui.emptyState.hidden = !empty;
    ui.messages.hidden = empty;
    if (empty && state.searchQuery) {
      ui.emptyTitle.textContent = "No matching messages";
      ui.emptyText.textContent = "Try a different search phrase.";
    } else if (empty) {
      ui.emptyTitle.textContent = "Nothing here yet.";
      ui.emptyText.textContent = "Send the first message. It is encrypted on this device before it leaves.";
    }
  }

  function appendMessage(message, options = {}) {
    const shouldStick = options.forceScroll !== false &&
      ui.messages.scrollHeight - ui.messages.scrollTop - ui.messages.clientHeight < 150;
    const day = dayKey(message.created_at);
    if (day !== state.lastRendered.day) {
      const sep = el("div", "day-sep");
      sep.append(el("span", "", dayLabel(message.created_at)));
      ui.messages.append(sep);
      state.lastRendered.day = day;
      state.lastRendered.device = null;
      state.lastRendered.at = 0;
    }

    const at = new Date(message.created_at).getTime();
    const grouped =
      state.lastRendered.device === message.device_id &&
      at - state.lastRendered.at < 5 * 60 * 1000;

    const mine = message.device_id === state.deviceId;
    const row = el(
      "div",
      `msg${mine ? " mine" : ""}${grouped ? " grouped" : ""}` +
        `${message.pending ? " pending" : ""}${message.failed ? " failed" : ""}`
    );
    row.dataset.cid = message.client_msg_id || "";

    if (!mine && !grouped) {
      const avatar = el("div", "avatar", initials(message.device_name));
      avatar.style.setProperty("--hue", hueOf(message.device_id));
      row.append(avatar);
    } else if (!mine) {
      const spacer = el("div", "avatar");
      spacer.style.visibility = "hidden";
      row.append(spacer);
    }

    const body = el("div", "body");
    if (!grouped) {
      const meta = el("div", "meta");
      meta.append(
        el("span", "who", mine ? "You" : message.device_name || "Device"),
        el("span", "time", clock(message.created_at))
      );
      body.append(meta);
    }

    const bubble = el("div", "bubble");
    if (message.failedDecrypt) {
      bubble.textContent = "⚠ This message could not be decrypted.";
      bubble.style.color = "var(--danger)";
    } else if (typeof message.text === "string" && message.text.startsWith("__TS_ATTACHMENT_V1__:")) {
      try {
        const file = JSON.parse(message.text.slice("__TS_ATTACHMENT_V1__:".length));
        const dataUrl = `data:${file.type || "application/octet-stream"};base64,${file.data}`;
        if (String(file.type || "").startsWith("audio/")) {
          const player = el("audio", "voice-player");
          player.controls = true;
          player.preload = "none";
          player.src = dataUrl;
          bubble.append(player);
          bubble.append(el("div", "voice-label", file.name || "Voice message"));
        }
        const link = el("a", "attachment-link", `📎 Download ${file.name || "attachment"}`);
        link.href = dataUrl;
        link.download = file.name || "attachment";
        link.rel = "noopener";
        bubble.append(link);
      } catch (_) { fillText(bubble, "Attachment could not be displayed."); }
    } else {
      fillText(bubble, message.text || "");
    }
    if (message.failed) {
      bubble.title = "Not sent — tap to retry";
      bubble.addEventListener("click", () => retryMessage(message));
    }
    if (message.reply_to_id) {
      const replied = state.messages.find((m) => String(m.id) === String(message.reply_to_id));
      body.append(el("div", "reply-reference", replied ? `↳ ${replied.device_name || "User"}: ${(replied.text || "Message").slice(0, 90)}` : "↳ Reply to a previous message"));
    }
    body.append(bubble);

    if (message.deleted) {
      bubble.classList.add("deleted-bubble");
    } else if (Number.isFinite(Number(message.id)) && !String(message.id).startsWith("tmp-")) {
      const actions = el("div", "message-actions");
      const actionButton = (label, title, handler) => {
        const button = el("button", "message-action", label);
        button.type = "button";
        button.title = title;
        button.addEventListener("click", handler);
        actions.append(button);
      };
      actionButton("↩", "Reply", () => {
        state.replyTo = message.id;
        ui.input.placeholder = `Reply to ${message.device_name || "user"} in #${currentRoom().name || "general"}`;
        ui.input.focus();
      });
      actionButton("☺", "React", () => reactToMessage(message));
      actionButton(message.pinned ? "📌" : "⌁", message.pinned ? "Unpin message" : "Pin message", () => togglePin(message));
      if (mine) {
        actionButton("Edit", "Edit message", () => editMessage(message));
        actionButton("Delete", "Delete message", () => deleteMessage(message));
      }
      body.append(actions);
      if (message.reactions && message.reactions.length) {
        const reactionBar = el("div", "reaction-bar");
        for (const reaction of message.reactions) {
          const chip = el("span", "reaction-chip", `${reaction.emoji} ${reaction.count}`);
          reactionBar.append(chip);
        }
        body.append(reactionBar);
      }
    }
    row.append(body);
    ui.messages.append(row);

    state.lastRendered.device = message.device_id;
    state.lastRendered.at = at;
    if (options.updateEmpty !== false) updateEmptyState();

    if (shouldStick) {
      scrollToBottom();
    } else if (options.track !== false) {
      state.newBelow += 1;
      updateJump();
    }
  }

  async function reactToMessage(message) {
    const emoji = window.prompt("Reaction emoji (for example 👍 ❤️ 😂 🎉):", "👍");
    if (!emoji || !emoji.trim()) return;
    try {
      const res = await api("/api/messages/react", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_id: message.id, emoji: emoji.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not add reaction.");
      message.reactions = data.reactions || [];
      renderMessages();
    } catch (err) {
      toast(err.message || "Could not add reaction.", "error");
    }
  }

  async function editMessage(message) {
    const next = window.prompt("Edit message:", message.text || "");
    if (next === null || next === message.text) return;
    if (!next.trim()) { toast("Message cannot be empty.", "error"); return; }
    try {
      const sealed = await encryptText(next, message.room_id);
      const res = await api("/api/messages/edit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_id: message.id, nonce: sealed.nonce, ciphertext: sealed.ciphertext }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not edit message.");
      message.text = next;
      message.edited_at = new Date().toISOString();
      renderMessages();
      toast("Message edited.");
    } catch (err) {
      toast(err.message || "Could not edit message.", "error");
    }
  }

  async function deleteMessage(message) {
    if (!window.confirm("Delete this message for everyone?")) return;
    try {
      const res = await api("/api/messages/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_id: message.id }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not delete message.");
      message.deleted = true;
      message.text = "Message deleted";
      message.reactions = [];
      renderMessages();
      toast("Message deleted.");
    } catch (err) {
      toast(err.message || "Could not delete message.", "error");
    }
  }

  async function togglePin(message) {
    const pinned = !message.pinned;
    try {
      const res = await api("/api/messages/pin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_id: message.id, pinned }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not update pin.");
      message.pinned = pinned;
      renderMessages();
      toast(pinned ? "Message pinned." : "Message unpinned.");
    } catch (err) {
      toast(err.message || "Could not update pin.", "error");
    }
  }

  function fillText(node, text) {
    const pattern = /(https?:\/\/[^\s<]+|@[A-Za-z0-9_-]{3,24})/g;
    let index = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      if (match.index > index) node.append(document.createTextNode(text.slice(index, match.index)));
      if (match[0].startsWith("http")) {
        const link = el("a", "", match[0]);
        link.href = match[0];
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        node.append(link);
      } else {
        const isMe = state.account?.username && match[0].slice(1).toLowerCase() === state.account.username.toLowerCase();
        node.append(el("span", isMe ? "mention mention-self" : "mention", match[0]));
      }
      index = match.index + match[0].length;
    }
    if (index < text.length) node.append(document.createTextNode(text.slice(index)));
  }

  function scrollToBottom(smooth = true) {
    state.newBelow = 0;
    ui.jumpBtn.hidden = true;
    ui.messages.scrollTo({
      top: ui.messages.scrollHeight,
      behavior: smooth ? "smooth" : "auto",
    });
  }

  function updateJump() {
    if (ui.messages.hidden) {
      ui.jumpBtn.hidden = true;
      return;
    }
    const distance =
      ui.messages.scrollHeight - ui.messages.scrollTop - ui.messages.clientHeight;
    if (distance < 240) {
      state.newBelow = 0;
      ui.jumpBtn.hidden = true;
      return;
    }
    ui.jumpBtn.hidden = false;
    ui.jumpBtn.textContent = state.newBelow > 0 ? `↓ ${state.newBelow} new` : "↓ Latest";
  }

  function notifyNew(message) {
    const room = state.rooms.find((r) => r.id === message.room_id);
    const roomName = room ? room.name : "channel";
    try {
      // Android WebView does not consistently implement the browser Notification API.
      // Use the native shell when present; it intentionally displays no message content.
      if (window.TerminusNative && typeof window.TerminusNative.notifyMessage === "function") {
        window.TerminusNative.notifyMessage(roomName);
        return;
      }
      if (!("Notification" in window) || Notification.permission !== "granted") return;
      const mentioned = state.account?.username && (message.text || "").toLowerCase().includes("@" + state.account.username.toLowerCase());
      const notification = new Notification(mentioned ? "You were mentioned" : "Terminus Secrets", {
        body: mentioned ? `You were mentioned in ${roomName}` : `New encrypted message in ${roomName}`,
        tag: `terminus-${message.room_id}`,
        silent: false,
      });
      notification.onclick = () => {
        window.focus();
        selectRoom(message.room_id);
        notification.close();
      };
    } catch (err) {
      /* notifications are optional */
    }
  }

  async function enableNotifications() {
    if (!("Notification" in window)) {
      toast("This browser does not support desktop notifications.", "error");
      return;
    }
    if (Notification.permission === "granted") {
      toast("Desktop notifications are already on.");
      return;
    }
    if (Notification.permission === "denied") {
      toast("Notifications are blocked in the browser settings.", "error");
      return;
    }
    const permission = await Notification.requestPermission();
    updateNotifyButton();
    toast(permission === "granted" ? "Desktop notifications enabled." : "Notifications were not enabled.");
  }

  function updateNotifyButton() {
    if (!("Notification" in window)) {
      ui.notifyBtn.textContent = "Notifications unavailable";
      ui.notifyBtn.disabled = true;
      return;
    }
    const permission = Notification.permission;
    ui.notifyBtn.textContent =
      permission === "granted"
        ? "Desktop notifications on"
        : permission === "denied"
        ? "Notifications blocked in browser"
        : "Enable desktop notifications";
    ui.notifyBtn.disabled = permission === "denied";
  }

  async function copyFingerprint() {
    const value = state.server?.fingerprint;
    if (!value) {
      toast("No fingerprint available yet.", "error");
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      toast("Fingerprint copied.");
    } catch (err) {
      const area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      toast("Fingerprint copied.");
    }
  }

  function updateMessageNode(message) {
    const node = ui.messages.querySelector(`.msg[data-cid="${CSS.escape(message.client_msg_id)}"]`);
    if (!node) return;
    node.classList.toggle("pending", Boolean(message.pending));
    node.classList.toggle("failed", Boolean(message.failed));
    const time = node.querySelector(".time");
    if (time) time.textContent = clock(message.created_at);
    const bubble = node.querySelector(".bubble");
    if (bubble) {
      bubble.title = message.failed ? "Not sent — tap to retry" : "";
      if (message.failed) bubble.onclick = () => retryMessage(message);
      else bubble.onclick = null;
    }
  }

  /* ------------------------------------------------------------------- send */
  function sendTyping(typing) {
    if (!state.token || !state.currentRoom) return;
    const now = Date.now();
    if (typing && now - state.typingLastSent < 1200) return;
    if (typing) state.typingLastSent = now;
    api("/api/typing", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room_id: state.currentRoom, typing: Boolean(typing) }),
    }).catch(() => {});
  }

  function autoGrow() {
    ui.input.style.height = "auto";
    ui.input.style.height = `${Math.min(ui.input.scrollHeight, 168)}px`;
  }

  function submitComposer() {
    const text = ui.input.value.replace(/\s+$/, "");
    if (!text.trim()) return;
    clearTimeout(state.typingTimer);
    sendTyping(false);
    const replyTo = state.replyTo;
    state.replyTo = null;
    ui.input.placeholder = `Message #${currentRoom().name || "general"}`;
    ui.input.value = "";
    autoGrow();
    sendText(text, replyTo);
  }

  async function sendText(text, replyToId = null) {
    if (!state.key) {
      toast("Vault is locked.", "error");
      return;
    }
    const roomId = state.currentRoom;
    const message = {
      id: `tmp-${uid()}`,
      client_msg_id: uid(),
      room_id: roomId,
      device_id: state.deviceId,
      device_name: state.deviceName,
      created_at: new Date().toISOString(),
      text,
      reply_to_id: replyToId,
      reactions: [],
      pinned: false,
      pending: true,
      failed: false,
    };
    state.messages.push(message);
    if (roomId === state.currentRoom) {
      appendMessage(message, { forceScroll: true });
      scrollToBottom();
    }
    await transmit(message);
  }

  async function transmit(message) {
    try {
      const sealed = await encryptText(message.text, message.room_id);
      const res = await api("/api/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          room_id: message.room_id,
          client_msg_id: message.client_msg_id,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
          reply_to_id: message.reply_to_id,
        }),
      });
      if (!res.ok) throw new Error(`send failed (${res.status})`);
      const data = await res.json();
      message.id = data.id;
      message.created_at = data.created_at || message.created_at;
      message.pending = false;
      message.failed = false;
      if (message.room_id === state.currentRoom) updateMessageNode(message);
    } catch (err) {
      message.pending = false;
      message.failed = true;
      if (message.room_id === state.currentRoom) updateMessageNode(message);
      toast("Message not sent. Tap the bubble to retry.", "error");
    }
  }

  async function retryMessage(message) {
    if (!message.failed) return;
    message.failed = false;
    message.pending = true;
    updateMessageNode(message);
    await transmit(message);
  }

  /* ------------------------------------------------------------------ rooms */
  async function refreshSync() {
    const res = await api(`/api/sync?after=${state.lastId}&wait=0`);
    if (!res.ok) throw new Error("Could not refresh server data.");
    await applySync(await res.json(), { quiet: true });
  }

  async function createServer() {
    const name = window.prompt("New server name:");
    if (name === null || !name.trim()) return;
    const description = window.prompt("Server description (optional):", "") || "";
    try {
      const res = await api("/api/servers/create", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: name.trim(), description }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not create server.");
      state.activeServerId = data.id;
      localStorage.setItem("ts.server", data.id);
      await refreshSync();
      const channel = state.rooms.find((room) => room.server_id === data.id && room.kind !== "dm");
      if (channel) selectRoom(channel.id); else renderRooms();
      toast(`Created ${data.name}. Invite code: ${data.invite_code}`);
      window.alert(`Server created: ${data.name}\\nInvite code (share only with people you want to join):\\n${data.invite_code}`);
    } catch (err) { toast(err.message || "Could not create server.", "error"); }
  }

  async function joinServer() {
    const invite_code = window.prompt("Paste the server invite code:");
    if (invite_code === null || !invite_code.trim()) return;
    try {
      const res = await api("/api/servers/join", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ invite_code: invite_code.trim() }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not join server.");
      state.activeServerId = data.id;
      localStorage.setItem("ts.server", data.id);
      await refreshSync();
      const channel = state.rooms.find((room) => room.server_id === data.id && room.kind !== "dm");
      if (channel) selectRoom(channel.id);
      toast(`Joined ${data.name}.`);
    } catch (err) { toast(err.message || "Could not join server.", "error"); }
  }

  function showServerInvite() {
    const server = state.servers.find((item) => item.id === state.activeServerId);
    if (!server) { toast("Create or join a server first.", "error"); return; }
    window.alert(`${server.name}\\nInvite code: ${server.invite_code || "Unavailable"}\\nShare this code only with people you want to join.`);
  }

  async function manageServerRoles() {
    const server = state.servers.find((item) => item.id === state.activeServerId);
    if (!server) { toast("Select a server first.", "error"); return; }
    if (server.role !== "owner") { toast("Only the server owner can manage member roles.", "error"); return; }
    const members = state.serverMembers.filter((member) => member.server_id === server.id);
    window.alert("Server members:\\n" + (members.map((member) => `${member.username} — ${member.role}`).join("\\n") || "No members loaded"));
    const username = window.prompt("Username of an existing server member:");
    if (username === null || !username.trim()) return;
    const role = window.prompt("Set role: type admin or member", "admin");
    if (role === null) return;
    const normalized = role.trim().toLowerCase();
    if (!["admin", "member"].includes(normalized)) { toast("Role must be admin or member.", "error"); return; }
    try {
      const res = await api("/api/servers/role", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ server_id: server.id, username: username.trim(), role: normalized }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not change role.");
      toast(`${username} is now ${normalized}.`);
      await refreshSync();
    } catch (err) { toast(err.message || "Could not change role.", "error"); }
  }

  async function openDirectMessage() {
    const username = window.prompt("Username(s) to message — separate multiple usernames with commas for a group DM:");
    if (username === null || !username.trim()) return;
    try {
      const res = await api("/api/dm/open", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: username.trim() }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not open direct message.");
      if (!state.rooms.some((room) => room.id === data.id)) state.rooms.push(data);
      selectRoom(data.id);
      toast(`Direct message with ${data.name} opened.`);
    } catch (err) { toast(err.message || "Could not open direct message.", "error"); }
  }

  async function sendAttachment() {
    const file = ui.fileInput.files && ui.fileInput.files[0];
    ui.fileInput.value = "";
    if (!file) return;
    if (file.size > 40 * 1024) { toast("For this encrypted chat build, attachments must be 40 KB or smaller.", "error"); return; }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const data = bytesToB64(bytes);
      const payload = "__TS_ATTACHMENT_V1__:" + JSON.stringify({ name: file.name.slice(0, 160), type: file.type || "application/octet-stream", data });
      await sendText(payload, null);
      toast(`Encrypted attachment sent: ${file.name}`);
    } catch (err) { toast(err.message || "Could not attach that file.", "error"); }
  }

  async function createRoom(event) {
    event.preventDefault();
    if (event.submitter && event.submitter.value === "cancel") {
      ui.roomDialog.close();
      return;
    }
    const name = ui.roomNameInput.value.trim().replace(/\s+/g, " ");
    const category = ui.roomCategoryInput.value.trim().replace(/\s+/g, " ");
    const description = ui.roomDescriptionInput.value.trim().replace(/\s+/g, " ");
    if (!name) {
      ui.roomError.textContent = "Give the group a name.";
      return;
    }
    ui.roomError.textContent = "";
    if (!state.activeServerId) {
      ui.roomError.textContent = "Create or join a server first.";
      return;
    }
    try {
      const res = await api("/api/rooms", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description, category, server_id: state.activeServerId, private: ui.roomPrivateInput.checked }),
      });
      if (!res.ok) {
        let detail = "Could not create the group.";
        try { detail = (await res.json()).error || detail; } catch (_) {}
        throw new Error(detail);
      }
      const room = await res.json();
      ui.roomDialog.close();
      ui.roomPrivateInput.checked = false;
      if (!state.rooms.some((r) => r.id === room.id)) state.rooms.push(room);
      selectRoom(room.id);
    } catch (err) {
      ui.roomError.textContent = err.message;
    }
  }

  async function manageRoom(room) {
    const choices = room.kind === "private" ? "rename, delete, or add-member" : "rename or delete";
    const choice = window.prompt(`Manage "${room.name}": type ${choices}`);
    if (choice === null) return;
    const action = choice.trim().toLowerCase();
    if (action === "add-member" && room.kind === "private") {
      const username = window.prompt("Username of a member who has already joined this server:");
      if (username === null || !username.trim()) return;
      try {
        const res = await api("/api/rooms/member", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ room_id: room.id, username: username.trim() }) });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || "Could not add private-channel member.");
        toast(`${username} added to #${room.name}.`);
        await refreshSync();
      } catch (err) { toast(err.message || "Could not add member.", "error"); }
      return;
    }
    if (action !== "rename" && action !== "delete") {
      toast("Choose rename, delete, or add-member for private channels.", "error");
      return;
    }
    let name = room.name;
    let description = room.description || "";
    if (action === "rename") {
      name = window.prompt("New group name:", room.name);
      if (name === null) return;
      name = name.trim().replace(/\s+/g, " ");
      if (!name) { toast("A group name is required.", "error"); return; }
      description = window.prompt("Group description:", description);
      if (description === null) return;
    } else if (!window.confirm(`Delete "${room.name}" and permanently remove its stored messages?`)) {
      return;
    }
    try {
      const res = await api("/api/rooms/manage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, room_id: room.id, name, description }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Group management failed.");
      if (action === "rename") {
        state.rooms = state.rooms.map((item) => item.id === room.id ? data : item);
        renderRooms();
        updateHeader();
        toast("Group renamed.");
      } else {
        state.rooms = state.rooms.filter((item) => item.id !== room.id);
        state.messages = state.messages.filter((item) => item.room_id !== room.id);
        state.unread.delete(room.id);
        if (state.currentRoom === room.id) {
          const nextRoom = state.rooms.find((item) => item.kind !== "dm" && item.server_id === state.activeServerId) || state.rooms[0];
          state.currentRoom = nextRoom?.id || "general";
          localStorage.setItem(LS.room, state.currentRoom);
          renderRooms();
          updateHeader();
          renderMessages();
        } else {
          renderRooms();
        }
        toast("Group deleted.");
      }
    } catch (err) {
      toast(err.message || "Group management failed.", "error");
    }
  }

  /* ------------------------------------------------------------------- info */
  function openInfo() {
    ui.infoHost.textContent = state.server
      ? `${state.server.server_name} · ${state.server.app} v${state.server.version}`
      : "—";
    ui.infoFingerprint.textContent = state.server?.fingerprint || "Unavailable";
    const list = document.createDocumentFragment();
    for (const device of state.devices) {
      const item = el("li");
      const dot = el("span", "dot" + (seenLabel(device.last_seen) === "online now" ? "" : " idle"));
      item.append(dot, el("span", "", device.name));
      if (device.id === state.deviceId) {
        item.append(el("span", "tag", "THIS DEVICE"));
      } else {
        const revoke = el("button", "revoke", "REVOKE");
        revoke.type = "button";
        revoke.title = `Revoke ${device.name}`;
        revoke.addEventListener("click", () => revokeDevice(device));
        item.append(revoke);
      }
      item.append(el("span", "when", seenLabel(device.last_seen)));
      list.append(item);
    }
    ui.deviceList.replaceChildren(list);
    ui.changeHostBtn.hidden = location.port !== "8756";
    updateNotifyButton();
    ui.infoDialog.showModal();
  }

  async function revokeDevice(device) {
    if (!window.confirm(`Revoke ${device.name}? That device will be signed out immediately.`)) return;
    try {
      const res = await api("/api/devices/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: device.id }),
      });
      if (!res.ok) throw new Error("The host refused the request.");
      state.devices = state.devices.filter((item) => item.id !== device.id);
      ui.infoDialog.close();
      toast(`${device.name} revoked.`);
      const sync = await api(`/api/sync?after=${state.lastId}&wait=0`);
      if (sync.ok) await applySync(await sync.json());
    } catch (err) {
      toast(err.message || "Could not revoke that device.", "error");
    }
  }

  function forgetToken() {
    state.token = "";
    state.deviceId = "";
    state.key = null;
    localStorage.removeItem(LS.token);
    localStorage.removeItem(LS.device);
    ui.chatView.hidden = true;
    ui.connectView.hidden = false;
    setMode("pair");
  }

  function lockOut(reason) {
    state.stopped = true;
    forgetToken();
    ui.connectError.textContent = reason || "Locked.";
  }

  function lockAndForget() {
    const sure = window.confirm(
      "Lock this device? The vault key is wiped from memory and the device token is removed. " +
        "You can re-pair with a fresh code."
    );
    if (!sure) return;
    state.stopped = true;
    state.key = null;
    forgetToken();
    ui.infoDialog.close();
    localStorage.removeItem(LS.room);
    location.reload();
  }

  /* -------------------------------------------------------------- saved hosts */
  function readSavedHosts() {
    try {
      const saved = JSON.parse(localStorage.getItem("ts.saved-hosts") || "[]");
      return Array.isArray(saved) ? saved.filter((item) => item && typeof item.url === "string").slice(0, 20) : [];
    } catch (_) { return []; }
  }

  function renderSavedHosts() {
    if (!ui.savedHostList) return;
    state.savedHosts = readSavedHosts();
    ui.savedHostList.replaceChildren();
    for (const host of state.savedHosts) {
      const button = el("button", "room-btn saved-host-btn");
      button.type = "button";
      button.title = host.url + " — reconnect requires your account, pairing code, and vault phrase";
      button.append(el("span", "hash", "↗"), el("span", "name", host.name || host.url));
      button.addEventListener("click", () => reconnectSavedHost(host));
      ui.savedHostList.append(button);
    }
    if (!state.savedHosts.length) ui.savedHostList.append(el("div", "host-empty", "No saved hosts yet"));
  }

  function normalizeHostAddress(raw) {
    let value = String(raw || "").trim();
    if (!value) throw new Error("Enter the host IPv6 address, for example https://[2001:db8::1]:8443.");
    if (!/^https:\/\//i.test(value)) value = "https://" + value;
    const parsed = new URL(value);
    if (parsed.protocol !== "https:") throw new Error("Hosts must use HTTPS.");
    if (!parsed.port) parsed.port = "8443";
    if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("Enter only the host address, without credentials or query parameters.");
    return { url: parsed.origin.replace(/\/$/, ""), name: parsed.hostname.replace(/^\[|\]$/g, "") };
  }

  function addSavedHost() {
    const raw = window.prompt("Host IPv6 address or HTTPS URL (example: https://[2001:db8::1]:8443):");
    if (raw === null) return;
    try {
      const host = normalizeHostAddress(raw);
      const list = readSavedHosts().filter((item) => item.url !== host.url);
      list.unshift(host);
      localStorage.setItem("ts.saved-hosts", JSON.stringify(list.slice(0, 20)));
      state.savedHosts = list.slice(0, 20);
      renderSavedHosts();
      toast("Saved host address. Reconnecting will require your account, pairing code, and vault phrase.");
    } catch (err) { toast(err.message || "Could not save host.", "error"); }
  }

  function reconnectSavedHost(host) {
    if (!window.confirm("Reconnect to " + host.url + "? You will need to sign in and enter that host’s pairing code and vault phrase. Credentials are not saved.")) return;
    const hostsJson = JSON.stringify(readSavedHosts());
    const query = "?tsSavedHosts=" + encodeURIComponent(hostsJson) + "&tsReconnect=1";
    if (window.TerminusNative && typeof window.TerminusNative.switchHost === "function") {
      window.TerminusNative.switchHost(host.url, hostsJson);
      return;
    }
    if (location.hostname === "127.0.0.1" && location.port === "8756") {
      const fingerprint = window.prompt("Enter the SHA-256 certificate fingerprint printed by the host console:");
      if (!fingerprint) return;
      fetch("/__trust", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: host.url, fingerprint }) })
        .then(async (res) => { const data = await res.json().catch(() => ({})); if (!data.ok) throw new Error(data.error || "Host fingerprint was not accepted."); location.href = "/app/" + query; })
        .catch((err) => toast(err.message || "Could not switch host.", "error"));
      return;
    }
    location.href = host.url + "/app/" + query;
  }

  async function restoreSavedHostsFromUrl() {
    const params = new URLSearchParams(location.search);
    const encoded = params.get("tsSavedHosts");
    if (encoded) {
      try {
        const incoming = JSON.parse(encoded);
        const merged = new Map(readSavedHosts().map((item) => [item.url, item]));
        if (Array.isArray(incoming)) incoming.slice(0, 20).forEach((item) => {
          if (item && typeof item.url === "string" && item.url.startsWith("https://")) merged.set(item.url, item);
        });
        state.savedHosts = Array.from(merged.values()).slice(0, 20);
        localStorage.setItem("ts.saved-hosts", JSON.stringify(state.savedHosts));
      } catch (_) {}
    }
    if (params.get("tsReconnect") === "1") {
      if (state.token && state.deviceId && state.accountToken) {
        try {
          await fetch("/api/devices/revoke", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": "Bearer " + state.token, "X-Account-Token": state.accountToken },
            body: JSON.stringify({ device_id: state.deviceId }),
          });
        } catch (_) {}
      }
      localStorage.removeItem(LS.token);
      localStorage.removeItem(LS.device);
      localStorage.removeItem(LS.accountToken);
      localStorage.removeItem(LS.account);
      state.token = "";
      state.deviceId = "";
      state.accountToken = "";
      state.account = null;
    }
    if (encoded || params.has("tsReconnect")) history.replaceState(null, "", location.pathname);
  }

  /* -------------------------------------------------------------- calls/media */
  function requireDirectMessage() {
    const room = currentRoom();
    if (!room || room.kind !== "dm") {
      toast("Calls and voice messages are available in direct messages.", "error");
      return false;
    }
    if (!state.key || !state.token || !state.accountToken) {
      toast("Sign in, pair this device, and unlock the vault first.", "error");
      return false;
    }
    return true;
  }

  async function sendCallSignal(roomId, kind, data = {}) {
    const sealed = await encryptText(JSON.stringify(data), roomId);
    const res = await api("/api/calls/signal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room_id: roomId, kind, payload: sealed }),
    });
    const result = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(result.error || "Could not send call signal.");
  }

  async function pollCallSignals() {
    if (state.callSignalBusy || !state.token || !state.accountToken || !state.key || state.stopped) return;
    const room = state.call ? state.rooms.find((item) => item.id === state.call.roomId) : currentRoom();
    if (!room || room.kind !== "dm") return;
    state.callSignalBusy = true;
    try {
      const cursor = state.callSignalCursor[room.id] || 0;
      const res = await api(`/api/calls/poll?room_id=${encodeURIComponent(room.id)}&after=${cursor}`);
      if (!res.ok) return;
      const data = await res.json();
      for (const signal of (data.signals || [])) {
        state.callSignalCursor[room.id] = Math.max(state.callSignalCursor[room.id] || 0, Number(signal.id) || 0);
        if (Date.now() - new Date(signal.created_at).getTime() > 120000) continue;
        let detail;
        try {
          const plain = await decryptMessage({ room_id: room.id, nonce: signal.payload?.nonce, ciphertext: signal.payload?.ciphertext });
          if (!plain) continue;
          detail = JSON.parse(plain);
        } catch (_) { continue; }
        await handleCallSignal(room.id, signal.kind, detail);
      }
    } catch (_) {
      // Calls reconnect independently from chat history.
    } finally {
      state.callSignalBusy = false;
    }
  }

  async function getCallMedia(mode) {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("This device/browser does not support microphone access.");
    }
    const constraints = {
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: mode === "video" ? { width: { ideal: 640 }, height: { ideal: 360 }, frameRate: { ideal: 20, max: 24 } } : false,
    };
    return navigator.mediaDevices.getUserMedia(constraints);
  }

  function makePeerConnection(roomId) {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    const call = state.call;
    call.pc = pc;
    pc.onicecandidate = (event) => {
      if (event.candidate && state.call === call) {
        sendCallSignal(roomId, "ice", { candidate: event.candidate.toJSON() }).catch(() => {});
      }
    };
    pc.ontrack = (event) => {
      const stream = event.streams?.[0];
      if (!stream) return;
      if (event.track.kind === "video") {
        ui.remoteCallVideo.srcObject = stream;
        ui.remoteCallVideo.hidden = false;
      } else {
        ui.remoteCallAudio.srcObject = stream;
      }
      ui.callStatus.textContent = "Connected";
    };
    pc.onconnectionstatechange = () => {
      if (state.call !== call) return;
      if (pc.connectionState === "connected") ui.callStatus.textContent = "Connected";
      if (["failed", "disconnected"].includes(pc.connectionState)) {
        ui.callStatus.textContent = "Connection unstable — this network may block direct peer connectivity.";
      }
    };
    return pc;
  }

  async function startCall(mode) {
    if (!requireDirectMessage()) return;
    if (state.call) { toast("A call is already active.", "error"); return; }
    const room = currentRoom();
    try {
      const stream = await getCallMedia(mode);
      state.call = { roomId: room.id, mode, pc: null, localStream: stream, shareStream: null, pendingIce: [], remoteDescriptionSet: false };
      ui.callPanel.hidden = false;
      ui.callTitle.textContent = mode === "video" ? "Video call" : "Voice call";
      ui.callStatus.textContent = "Calling…";
      ui.localCallVideo.srcObject = stream;
      ui.localCallVideo.hidden = mode !== "video";
      ui.remoteCallVideo.hidden = mode !== "video";
      const pc = makePeerConnection(room.id);
      stream.getTracks().forEach((track) => pc.addTrack(track, stream));
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendCallSignal(room.id, "offer", { description: { type: pc.localDescription.type, sdp: pc.localDescription.sdp }, mode });
      ui.screenCallBtn.disabled = false;
      ui.shareCallBtn.disabled = false;
    } catch (err) {
      await endCall(false);
      toast(err.message || "Could not start call. Check microphone/camera permissions.", "error");
    }
  }

  async function handleCallSignal(roomId, kind, detail) {
    if (kind === "offer") {
      if (state.call) {
        await sendCallSignal(roomId, "busy", {});
        return;
      }
      if (!window.confirm("Incoming " + (detail.mode === "video" ? "video" : "voice") + " call. Answer?")) {
        await sendCallSignal(roomId, "reject", {});
        return;
      }
      try {
        const mode = detail.mode === "video" ? "video" : "audio";
        const stream = await getCallMedia(mode);
        state.call = { roomId, mode, pc: null, localStream: stream, shareStream: null, pendingIce: [], remoteDescriptionSet: false };
        ui.callPanel.hidden = false;
        ui.callTitle.textContent = mode === "video" ? "Video call" : "Voice call";
        ui.callStatus.textContent = "Answering…";
        ui.localCallVideo.srcObject = stream;
        ui.localCallVideo.hidden = mode !== "video";
        ui.remoteCallVideo.hidden = mode !== "video";
        const pc = makePeerConnection(roomId);
        stream.getTracks().forEach((track) => pc.addTrack(track, stream));
        await pc.setRemoteDescription(detail.description);
        state.call.remoteDescriptionSet = true;
        for (const candidate of state.call.pendingIce.splice(0)) await pc.addIceCandidate(candidate);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await sendCallSignal(roomId, "answer", { description: { type: pc.localDescription.type, sdp: pc.localDescription.sdp } });
        ui.screenCallBtn.disabled = false;
        ui.shareCallBtn.disabled = false;
      } catch (err) {
        await endCall(false);
        toast(err.message || "Could not answer call.", "error");
      }
      return;
    }
    if (!state.call || state.call.roomId !== roomId) return;
    try {
      if (kind === "answer" && detail.description && state.call.pc) {
        await state.call.pc.setRemoteDescription(detail.description);
        state.call.remoteDescriptionSet = true;
        for (const candidate of state.call.pendingIce.splice(0)) await state.call.pc.addIceCandidate(candidate);
        ui.callStatus.textContent = "Connecting…";
      } else if (kind === "ice" && detail.candidate && state.call.pc) {
        if (state.call.remoteDescriptionSet) await state.call.pc.addIceCandidate(detail.candidate);
        else state.call.pendingIce.push(detail.candidate);
      } else if (kind === "hangup" || kind === "reject" || kind === "busy") {
        const message = kind === "busy" ? "The other person is already in a call." : kind === "reject" ? "Call declined." : "The other person ended the call.";
        await endCall(false);
        toast(message);
      }
    } catch (_) {}
  }

  async function toggleScreenShare() {
    if (!state.call?.pc) { toast("Start a call first.", "error"); return; }
    if (state.call.shareStream) {
      const cameraTrack = state.call.localStream.getVideoTracks()[0];
      const sender = state.call.pc.getSenders().find((item) => item.track?.kind === "video");
      if (sender) await sender.replaceTrack(cameraTrack || null);
      state.call.shareStream.getTracks().forEach((track) => track.stop());
      state.call.shareStream = null;
      ui.localCallVideo.srcObject = state.call.localStream;
      ui.shareCallBtn.textContent = "Share screen";
      toast("Screen sharing stopped.");
      return;
    }
    if (!navigator.mediaDevices?.getDisplayMedia) {
      toast("Screen sharing is not supported by this browser/device.", "error");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: 15 }, audio: false });
      const track = stream.getVideoTracks()[0];
      const sender = state.call.pc.getSenders().find((item) => item.track?.kind === "video");
      if (sender) await sender.replaceTrack(track);
      else state.call.pc.addTrack(track, stream);
      state.call.shareStream = stream;
      ui.localCallVideo.srcObject = stream;
      ui.localCallVideo.hidden = false;
      ui.shareCallBtn.textContent = "Stop sharing";
      track.onended = () => { if (state.call?.shareStream) toggleScreenShare(); };
    } catch (err) {
      toast(err.message || "Screen sharing was cancelled or blocked.", "error");
    }
  }

  function toggleCallMute() {
    const tracks = state.call?.localStream?.getAudioTracks() || [];
    if (!tracks.length) return;
    const next = !tracks[0].enabled;
    tracks.forEach((track) => { track.enabled = next; });
    ui.muteCallBtn.textContent = next ? "Mute mic" : "Unmute mic";
  }

  function toggleCallCamera() {
    const tracks = state.call?.localStream?.getVideoTracks() || [];
    if (!tracks.length) { toast("This call has no camera track.", "error"); return; }
    const next = !tracks[0].enabled;
    tracks.forEach((track) => { track.enabled = next; });
    ui.cameraCallBtn.textContent = next ? "Camera off" : "Camera on";
  }

  async function endCall(notifyPeer = false) {
    const call = state.call;
    state.call = null;
    if (call) {
      if (notifyPeer) sendCallSignal(call.roomId, "hangup", {}).catch(() => {});
      try { call.pc?.close(); } catch (_) {}
      for (const stream of [call.localStream, call.shareStream]) stream?.getTracks().forEach((track) => track.stop());
    }
    ui.callPanel.hidden = true;
    ui.localCallVideo.srcObject = null;
    ui.remoteCallVideo.srcObject = null;
    ui.remoteCallAudio.srcObject = null;
    ui.screenCallBtn.disabled = true;
    ui.shareCallBtn.textContent = "Share screen";
    ui.muteCallBtn.textContent = "Mute mic";
    ui.cameraCallBtn.textContent = "Camera off";
  }

  async function toggleVoiceRecording() {
    if (!requireDirectMessage()) return;
    if (state.voiceRecorder && state.voiceRecorder.state === "recording") {
      state.voiceRecorder.stop();
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
      toast("Voice recording is not supported by this browser/device.", "error");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
      const mime = ["audio/webm;codecs=opus", "audio/ogg;codecs=opus"].find((type) => MediaRecorder.isTypeSupported(type)) || "";
      const recorder = new MediaRecorder(stream, mime ? { mimeType: mime, audioBitsPerSecond: 24000 } : { audioBitsPerSecond: 24000 });
      state.voiceRecorder = recorder;
      state.voiceChunks = [];
      recorder.ondataavailable = (event) => { if (event.data?.size) state.voiceChunks.push(event.data); };
      recorder.onstop = async () => {
        stream.getTracks().forEach((track) => track.stop());
        ui.voiceMessageBtn.classList.remove("recording");
        ui.voiceMessageBtn.textContent = "🎙";
        ui.voiceMessageBtn.title = "Record voice message (max 10 seconds)";
        clearTimeout(state.voiceStopTimer);
        const blob = new Blob(state.voiceChunks, { type: recorder.mimeType || "audio/webm" });
        state.voiceRecorder = null;
        state.voiceChunks = [];
        if (!blob.size) return;
        if (blob.size > 43000) { toast("Voice note is too large; record a shorter one.", "error"); return; }
        const data = bytesToB64(new Uint8Array(await blob.arrayBuffer()));
        const ext = blob.type.includes("ogg") ? "ogg" : "webm";
        await sendText("__TS_ATTACHMENT_V1__:" + JSON.stringify({ name: "voice-message." + ext, type: blob.type || "audio/webm", data }), null);
      };
      recorder.start(250);
      ui.voiceMessageBtn.classList.add("recording");
      ui.voiceMessageBtn.textContent = "■";
      ui.voiceMessageBtn.title = "Stop recording voice message";
      toast("Recording voice message… tap ■ to send.");
      state.voiceStopTimer = setTimeout(() => {
        if (state.voiceRecorder?.state === "recording") state.voiceRecorder.stop();
      }, 10000);
    } catch (err) {
      toast(err.message || "Microphone permission was denied.", "error");
    }
  }

  /* ------------------------------------------------------------------- init */
  async function init() {
    await restoreSavedHostsFromUrl();
    cacheUi();
    bindEvents();
    ui.deviceInput.value = state.deviceName;
    ui.accountTitle = $("#accountTitle");
    ui.accountPanel.hidden = Boolean(state.accountToken);
    ui.connectForm.hidden = !state.accountToken;
    if (state.account) {
      ui.accountUsername.value = state.account.username || "";
    }
    const reachable = await checkHost();
    if (state.accountToken && state.token) setMode("unlock");
    else setMode("pair");
    if (!reachable) {
      ui.connectError.textContent =
        "The host is not reachable. Start host.py on your laptop, then reload.";
    }
    updateEmptyState();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
