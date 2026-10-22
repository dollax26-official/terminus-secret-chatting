"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

const css = read("server/web/styles.css");
const client = read("server/web/app.js");
const electron = read("windows-app/electron/main.js");
const html = read("server/web/index.html");

assert.match(css, /body\s*,\s*body\s*\*\s*\{[^}]*user-select:\s*text\s*;/s,
  "Shared UI must explicitly allow text selection");
assert.match(css, /-webkit-user-select:\s*text\s*;/,
  "Shared UI must enable selection in Chromium/WebView");
assert.doesNotMatch(css, /user-select:\s*none\s*;/,
  "Shared UI must not globally disable text selection");
assert.match(client, /navigator\.clipboard\.writeText/,
  "Web client must use the Clipboard API where available");
assert.match(client, /document\.execCommand\(["']copy["']\)/,
  "Web client must keep a legacy copy fallback");
assert.match(electron, /webContents\.on\(["']context-menu["']/,
  "Windows app must expose a native context menu");
assert.match(electron, /role:\s*["']copy["']/,
  "Windows context menu must offer Copy");
assert.match(electron, /role:\s*["']paste["']/,
  "Windows context menu must offer Paste");
assert.match(electron, /role:\s*["']selectAll["']/,
  "Windows context menu must offer Select All");
assert.doesNotMatch(html, /user-scalable\s*=\s*no/i,
  "Mobile UI must not disable zoom");

console.log("PASS  shared UI text selection, clipboard fallback, Windows copy/paste menu, mobile zoom");
