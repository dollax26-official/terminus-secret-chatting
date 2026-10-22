# UI quality checklist for Terminus Secrets

This checklist applies to the shared web client (server/web/) because both the Android WebView and Windows Electron client render it. The native shells cannot compensate for a broken shared screen.

## Source used

Reviewed against [UI Guides & Agent Rules](https://github.com/strongeron/ui-guides-agent-rules) and its [agent-ready principle index](https://ui-guides-agent-rules.netlify.app/principles/index.md). The source recommends searching the index by UI surfaces and concrete symbols, then opening only matching individual rules rather than downloading the 169k-token full corpus.

## Rules applied in this pass

- Forms: visible labels, meaningful placeholders, required-field validation, inline errors, and disabled/loading feedback while requests are pending.
- Dialogs: keep create-server, join-server, DM, host-add, invite, and certificate-trust actions inside the app's dialog system; preserve typed values after failures.
- Keyboard and accessibility: semantic buttons, accessible names, visible focus outlines, and live error/status messages.
- Responsive layout: shared controls remain available in the Android WebView sidebar at narrow widths; dialogs fit the viewport and preserve scroll.
- Media: clearly report unsupported camera/microphone/screen-capture APIs; release media tracks when a call ends.
- Performance: avoid heavy UI dependencies; show memory planning estimates as estimates, not measured RAM or a hard limit.
- Destructive actions: explicitly confirm deleting a server/channel and explain that associated history is removed.

## Validation standard

Run python -m py_compile server/host.py server/settings_app.py, python tools/smoke_test.py, node --check server/web/app.js, and node --check windows-app/electron/main.js. Build the Android APK and Windows EXE in CI. These checks prove source/package health, not successful live calls across arbitrary carrier NATs; test voice/video/screen sharing on target devices and networks separately.
