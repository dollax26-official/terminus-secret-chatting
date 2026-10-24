const { app, BrowserWindow, Menu, dialog, shell, session } = require("electron");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const path = require("path");
const { URL } = require("url");

const APP_NAME = "Terminus Secrets";
const PROXY_PORT = 8756;
const MAX_BODY = 2 * 1024 * 1024;

const CONFIG_DIR = path.join(app.getPath("appData"), "TerminusSecrets");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const LOG_PATH = path.join(CONFIG_DIR, "electron.log");

let config = {};
let mainWindow = null;
let proxyServer = null;

/* ------------------------------------------------------------------ utils */
function log(message) {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace("T", " ").slice(0, 19);
    fs.appendFileSync(LOG_PATH, `${stamp}  ${message}\n`);
  } catch (err) {
    /* logging must never break the app */
  }
}

function loadConfig() {
  try {
    const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
    if (parsed && typeof parsed === "object") return parsed;
  } catch (err) {
    /* first run */
  }
  return {};
}

function saveConfig(next) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  const tmp = `${CONFIG_PATH}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(next, null, 2), "utf8");
  fs.renameSync(tmp, CONFIG_PATH);
}

function normalizePin(pin) {
  return String(pin || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

function samePin(a, b) {
  const left = Buffer.from(normalizePin(a), "hex");
  const right = Buffer.from(normalizePin(b), "hex");
  if (!left.length || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function requestHostname(targetUrl) {
  // WHATWG URL.hostname keeps brackets around IPv6 literals, but Node's
  // https.request({ hostname }) expects the bare IPv6 address.
  const hostname = targetUrl.hostname;
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function fingerprintOf(certificate) {
  if (!certificate || !certificate.raw) return "";
  return crypto.createHash("sha256").update(certificate.raw).digest("hex");
}

function certToPem(certificate) {
  if (!certificate || !certificate.raw) return "";
  const body = certificate.raw.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

function sendJson(response, status, payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
  });
  response.end(body);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    request.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY) {
        reject(new Error("body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function serveFile(response, filename, contentType) {
  try {
    const data = fs.readFileSync(path.join(__dirname, filename));
    response.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": data.length,
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy":
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:",
    });
    response.end(data);
  } catch (err) {
    response.writeHead(500, { "Content-Length": 0 });
    response.end();
  }
}

/* ------------------------------------------------------------------ probe */
function probeHost(rawUrl) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(rawUrl);
    } catch (err) {
      reject(new Error("That does not look like a valid URL."));
      return;
    }
    if (target.protocol !== "https:") {
      reject(new Error("The host address must start with https://"));
      return;
    }

    const request = https.request(
      {
        protocol: "https:",
        hostname: requestHostname(target),
        port: target.port || 443,
        path: "/api/health",
        method: "GET",
        headers: { Accept: "application/json" },
        rejectUnauthorized: false,
        agent: false,
        timeout: 12000,
      },
      (upstream) => {
        let body = "";
        upstream.setEncoding("utf8");
        upstream.on("data", (chunk) => {
          body += chunk;
        });
        upstream.on("end", () => {
          try {
            const certificate = upstream.socket.getPeerCertificate(true);
            const fingerprint = fingerprintOf(certificate);
            if (!fingerprint) throw new Error("The host did not present a certificate.");
            if (upstream.statusCode !== 200) {
              throw new Error(`The host answered HTTP ${upstream.statusCode}.`);
            }
            const health = JSON.parse(body);
            if (health.app !== "terminus-secrets") {
              throw new Error("That address is not a Terminus Secrets host.");
            }
            resolve({
              ok: true,
              url: rawUrl.replace(/\/+$/, ""),
              host: target.hostname,
              port: Number(target.port || 443),
              fingerprint,
              cert_pem: certToPem(certificate),
              server_name: health.server_name || target.hostname,
              version: health.version || "?",
            });
          } catch (err) {
            reject(err);
          }
        });
      }
    );

    request.on("timeout", () => request.destroy(new Error("Connection timed out.")));
    request.on("error", reject);
    request.end();
  });
}

/* ------------------------------------------------------------------ proxy */
function forward(request, response) {
  if (!config.server_url || !config.fingerprint) {
    response.writeHead(302, { Location: "/setup", "Content-Length": 0 });
    response.end();
    return;
  }

  const target = new URL(config.server_url);
  const headers = {};
  for (const name of ["authorization", "content-type", "accept", "user-agent"]) {
    if (request.headers[name]) headers[name] = request.headers[name];
  }
  headers["accept-encoding"] = "identity";

  const upstream = https.request({
    protocol: "https:",
    hostname: requestHostname(target),
    port: target.port || 443,
    path: request.url,
    method: request.method,
    headers,
    rejectUnauthorized: false,
    agent: false,
    timeout: 60000,
  });

  // The TLS handshake finishes before any HTTP bytes are written, so a wrong
  // certificate stops the request before the token can leave the machine.
  upstream.on("socket", (socket) => {
    socket.once("secureConnect", () => {
      const seen = fingerprintOf(socket.getPeerCertificate(true));
      if (!samePin(seen, config.fingerprint)) {
        upstream.destroy(new Error("host certificate pin mismatch"));
      }
    });
  });

  upstream.on("timeout", () => upstream.destroy(new Error("host timed out")));

  upstream.on("response", (remote) => {
    const seen = fingerprintOf(remote.socket.getPeerCertificate(true));
    if (!samePin(seen, config.fingerprint)) {
      remote.destroy();
      sendJson(response, 502, { error: "host identity check failed; re-run setup" });
      return;
    }

    const outHeaders = {};
    for (const name of [
      "content-type",
      "cache-control",
      "content-security-policy",
      "x-content-type-options",
      "x-frame-options",
      "referrer-policy",
      "permissions-policy",
      "service-worker-allowed",
      "location",
    ]) {
      if (remote.headers[name]) outHeaders[name] = remote.headers[name];
    }
    response.writeHead(remote.statusCode || 502, outHeaders);
    remote.pipe(response);
  });

  upstream.on("error", (err) => {
    log(`proxy error: ${err.message}`);
    if (!response.headersSent) {
      sendJson(response, 502, { error: `host unreachable: ${err.message}` });
    } else {
      response.destroy();
    }
  });

  request.pipe(upstream);
}

function handleRequest(request, response) {
  const parsed = new URL(request.url, `http://127.0.0.1:${PROXY_PORT}`);
  const pathname = parsed.pathname;

  if (pathname === "/setup" || pathname === "/setup/") {
    serveFile(response, "setup.html", "text/html; charset=utf-8");
    return;
  }

  if (pathname === "/__state") {
    sendJson(response, 200, {
      configured: Boolean(config.server_url && config.fingerprint),
      server_url: config.server_url || "",
      server_name: config.server_name || "",
      fingerprint: config.fingerprint || "",
    });
    return;
  }

  if (pathname === "/__probe") {
    const target = parsed.searchParams.get("url") || "";
    probeHost(target)
      .then((info) => sendJson(response, 200, info))
      .catch((err) => sendJson(response, 200, { ok: false, error: err.message }));
    return;
  }

  if (pathname === "/__trust" && request.method === "POST") {
    const origin = request.headers.origin;
    if (origin && origin !== `http://127.0.0.1:${PROXY_PORT}`) {
      sendJson(response, 403, { ok: false, error: "bad origin" });
      return;
    }
    readBody(request)
      .then(async (buffer) => {
        const body = JSON.parse(buffer.toString("utf8") || "{}");
        const url = String(body.url || "").replace(/\/+$/, "");
        const claimed = String(body.fingerprint || "");
        // Never trust the page: re-probe the live host and compare again.
        const info = await probeHost(url);
        if (!samePin(info.fingerprint, claimed)) {
          throw new Error("the host certificate changed during setup");
        }
        config = {
          server_url: info.url,
          fingerprint: info.fingerprint,
          cert_pem: info.cert_pem,
          server_name: info.server_name,
          paired_at: new Date().toISOString(),
        };
        saveConfig(config);
        log(`trusted host ${info.url} pin=${info.fingerprint.slice(0, 16)}...`);
        sendJson(response, 200, { ok: true });
      })
      .catch((err) => sendJson(response, 200, { ok: false, error: err.message }));
    return;
  }

  if (pathname === "/") {
    response.writeHead(302, {
      Location: config.server_url ? "/app/" : "/setup",
      "Content-Length": 0,
    });
    response.end();
    return;
  }

  if (!(pathname === "/app" || pathname.startsWith("/app/") || pathname.startsWith("/api/"))) {
    response.writeHead(404, { "Content-Length": 0 });
    response.end();
    return;
  }

  forward(request, response);
}

function startProxy() {
  return new Promise((resolve, reject) => {
    proxyServer = http.createServer((req, res) => {
      try {
        handleRequest(req, res);
      } catch (err) {
        log(`request error: ${err.message}`);
        if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
      }
    });
    proxyServer.on("error", reject);
    proxyServer.listen(PROXY_PORT, "127.0.0.1", () => {
      log(`proxy listening on ${PROXY_PORT}`);
      resolve();
    });
  });
}

/* ------------------------------------------------------------------ window */
function isLocal(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname === "127.0.0.1" && Number(parsed.port) === PROXY_PORT;
  } catch (err) {
    return false;
  }
}

function createWindow(startPath) {
  mainWindow = new BrowserWindow({
    width: 1220,
    height: 800,
    minWidth: 940,
    minHeight: 620,
    backgroundColor: "#06090e",
    icon: path.join(__dirname, "icon.ico"),
    show: false,
    autoHideMenuBar: true,
    title: APP_NAME,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true,
    },
  });

  Menu.setApplicationMenu(null);
  mainWindow.once("ready-to-show", () => mainWindow.show());

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (!isLocal(url)) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  mainWindow.loadURL(`http://127.0.0.1:${PROXY_PORT}${startPath}`);
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

async function main() {
  // Only the bundled client served from our loopback proxy may request media.
  // This is required for voice/video calls in the packaged Windows app; without
  // an explicit handler Electron may deny getUserMedia even after user consent.
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const requestingUrl = details && details.requestingUrl;
    const trustedClient = Boolean(webContents && !webContents.isDestroyed() && isLocal(requestingUrl));
    const allowed = trustedClient && (permission === "media" || permission === "display-capture");
    if (!allowed) log(`denied permission ${permission} from ${requestingUrl || "unknown origin"}`);
    callback(allowed);
  });

  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return;
  }
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  config = loadConfig();
  try {
    await startProxy();
  } catch (err) {
    dialog.showErrorBox(
      "Terminus Secrets",
      `Port ${PROXY_PORT} is already in use. Close the other copy and try again.`
    );
    app.quit();
    return;
  }

  let startPath = "/setup";
  const forceSetup = process.argv.includes("--setup");
  if (!forceSetup && config.server_url && config.fingerprint) {
    try {
      const info = await probeHost(config.server_url);
      if (samePin(info.fingerprint, config.fingerprint)) {
        startPath = "/app/";
      } else {
        log("pin mismatch at startup; opening setup");
      }
    } catch (err) {
      log(`startup probe failed: ${err.message}`);
    }
  }

  createWindow(startPath);
}

app.whenReady().then(main);

app.on("window-all-closed", () => {
  if (proxyServer) proxyServer.close();
  app.quit();
});

process.on("uncaughtException", (err) => log(`uncaught: ${err.stack || err.message}`));
