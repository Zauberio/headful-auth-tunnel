# Changelog

## 0.4.5 - 2026-09-05

### Login iframe stability

- Ignore transient subframes that have not committed a URL yet instead of quarantining the entire page. Empty/unreadable main-frame URLs remain fail-closed.
- Log every page quarantine with the current page URL and the reason before navigating to `about:blank`, making screenshot/read-boundary failures diagnosable.
- Add an explicit **Drag: Off/On** UI mode: normal clicks use the stable `/click` path by default, while Drag mode uses continuous pointer down/move/up events for human-operated sliders and similar controls.
- Keep the normal screenshot refresh interval at the configured/default 2 seconds in both click and drag modes.

## 0.4.4 - 2026-09-04

### Browser safety and authentication

- Raise the default DNS validation budget to 512 distinct network origins per 5-second window and make it configurable with `DNS_VALIDATION_MAX_EVENTS`.
- Reuse a fresh DNS decision for repeated events from the same origin inside the budget window instead of consuming budget and forcing a lookup on every iframe/redirect/read-boundary event. Distinct origins remain fail-closed when the budget is exhausted.
- Replace restart-local UI sessions with signed per-browser/device session cookies that survive tunnel restarts. The access token is never stored in the browser cookie.
- Set browser-session lifetime to 30 days by default and make it configurable with `SESSION_TTL_SECONDS`. Rotating the master access token invalidates all outstanding browser sessions.
- Rename the UI keyboard text button from `Type` to `Send`; the HTTP API remains `POST /type` for compatibility.

## 0.4.3 - 2026-09-03

### Browser ownership

- Add `BROWSER_MODE=managed|cdp` and separate browser lifecycle ownership from the authenticated control surface.
- Add attach-only CDP mode with `CDP_ENDPOINT` and explicit `CDP_TARGET` tab selection.
- In CDP mode, never open `PROFILE_DIR`, launch Chromium or close the externally owned browser on detach.
- Scope the tunnel to the selected external tab and its descendant popups instead of adopting unrelated browser tabs.
- Fail closed if the attached external tab disappears instead of creating a replacement tab in a browser the tunnel does not own.
- Preserve the v0.4.2 redirect, frame-navigation and final-landing guards for attached pages.
- Add `/meta` fields `browser_backend` and `browser_owner`.
- Make Playwright an explicit package dependency for CDP attachment.
- Fix package/server version metadata so the release reports `0.4.3` consistently.

## 0.4.1 - 2026-08-07

- Add opt-in `TRUST_FORWARDED_PROTO` support so deployments behind a controlled HTTPS reverse proxy can still emit `Secure` session cookies.
- Add optional `BROWSER_EXECUTABLE_PATH` so deployments can use an existing Chromium/Chrome installation instead of Patchright's bundled browser.

## 0.4.0 - 2026-08-07

- Use generic `en-US`/`UTC` browser defaults for the public package while keeping locale/timezone configurable.
- Bound `/type` input with `MAX_TYPE_TEXT_CHARS` and reject overlong navigation URLs with `MAX_URL_CHARS` before parsing/DNS.

### Security

- Replace URL/local-storage token propagation with a login form and random `HttpOnly`, `SameSite=Strict` session cookie.
- Keep legacy query-string authentication disabled by default and redact query strings from access logs.
- Add constant-time bearer-token comparison, request-size limits, socket timeouts, no-store responses, CSP, clickjacking protection, MIME sniffing protection and strict referrer policy.
- Allow public websites by default while blocking loopback, private, link-local, reserved and common internal destinations.
- Apply destination policy to top-level navigation, redirects, subresources and WebSockets, with explicit allow/deny overrides.
- Keep sensitive DOM values out of routine snapshots while allowing the authenticated operator to reveal them explicitly for login, OTP and token workflows.

### Browser control

- Make viewport, locale and timezone configuration effective while preserving `1440×1100`, `pt-PT` and `Europe/Lisbon` defaults.
- Add runtime viewport editing up to `7680×4320`.
- Scale pointer coordinates from the screenshot's real dimensions; validate end-to-end at `3840×2160`.
- Add tab/popup listing, focus and close operations.
- Add DOM snapshot, selector fill, click, press and select operations, including explicit sensitive-value inspection.
- Keep one live headful Chromium context for every tunnel process and reuse the same persistent profile across restarts.
- Move Playwright work to a dedicated browser thread so concurrent HTTP clients cannot cross Playwright thread boundaries.

### Operations and packaging

- Preserve the existing `127.0.0.1:19192` network defaults.
- Harden start/stop scripts with PID ownership checks, Xvfb lifecycle tracking and readiness checks.
- Add token-display and foreground-run helpers.
- Add explicit PEP 517 build metadata, bounded Scrapling dependency and Python 3.10–3.14 classifiers.
- Add Docker, Docker Compose and systemd examples.
- Add pytest coverage, Ruff, ShellCheck, GitHub Actions CI, Dependabot and tagged-release builds.

## 0.2.0 - 2026-06-03

- Add human drag/pointer support with real pointer down / move / up events.
- Add coordinate-based drag assist for high-latency sessions.
- Simplify the remote-control UI around common human handoff actions.
- Document slider-friendly human control while keeping CAPTCHA/anti-bot bypass as a non-goal.

## 0.1.0 - Initial public release

- Initial LAN/VPN headful browser auth tunnel with persistent profiles, screenshot stream, click/type/key/paste/back/navigation controls and session marker saving.
