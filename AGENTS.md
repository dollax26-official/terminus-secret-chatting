# Terminus Secrets — contributor rules

## UI review source
Before changing the shared web client, consult [UI Guides & Agent Rules](https://github.com/strongeron/ui-guides-agent-rules) and search its [principle index](https://ui-guides-agent-rules.netlify.app/principles/index.md) for the surfaces actually touched. Use only relevant individual rules and keep attribution to their original authors.

## Required UI behavior
- **MUST** use the UI Guides rules as a targeted checklist: inspect form, button, dialog, keyboard-focus, responsive-layout, media, and performance rules relevant to the changed components; don't load the entire corpus.
- **MUST** test the shared client at narrow Android widths and desktop widths; don't rely on screenshots or syntax checks alone.
- **MUST** use semantic buttons for actions, labels for inputs, and visible keyboard focus; do not make clickable `div` elements.
- **MUST** give forms an explicit submit path, inline error text, disabled/loading feedback while a request is in flight, and preserve typed values after recoverable failures.
- **MUST** keep actions available on narrow Android WebView screens; test at 360 px width and desktop widths. Use touch targets of at least 40 px where layout permits.
- **MUST** make destructive actions explicit, explain what data is removed, and require confirmation before deleting a server/channel.
- **MUST** respect `prefers-reduced-motion`; avoid layout shifts, horizontal page overflow, and unnecessary animated decoration.
- **MUST** not imply a call or screen share works when browser/WebView permissions or platform APIs are unavailable. Show a clear, actionable error.
- **SHOULD** prefer inline dialogs and toasts over browser prompt/alert dialogs. Member-role and private-channel access changes use labeled, inline forms with recoverable errors.
- **SHOULD** keep the shared `server/web/` interface as the source of truth for both Android and Windows clients.
- **SHOULD** keep background polling modest, stop media tracks when a call ends, and avoid large bundled assets to reduce memory use.

## Validation before claiming completion
- Run `python -m py_compile server/host.py` and `python tools/smoke_test.py`.
- Run `node --check server/web/app.js` and `node --check windows-app/electron/main.js`.
- Build the Windows EXE and Android APK through CI; report platform limitations separately from source-level checks.
- Do not claim a feature is production-ready based only on syntax checks or successful packaging.
