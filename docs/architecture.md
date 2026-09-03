# Architecture

## Overview

Headful Auth Tunnel exposes one human-operated browser surface through a small authenticated HTTP service. Browser ownership is explicit and selectable.

```text
remote browser or API client
        |
        | HTTP(S), session cookie or bearer token
        v
ThreadingHTTPServer
        |
        | bounded command queue
        v
single browser worker thread
        |
        v
BrowserBackend
   |                     |
   | managed             | cdp
   v                     v
Scrapling             Playwright CDP client
StealthySession           |
   |                      v
   v                 externally owned Chromium
managed Chromium      and persistent profile
   |
   v
PROFILE_DIR
```

The HTTP/API surface is the same in both modes. The browser worker remains the only thread that touches Playwright/browser objects.

## Browser backends

### Managed backend

`BROWSER_MODE=managed` is the standalone/default mode. The tunnel launches one headed Chromium through Scrapling `StealthySession`, owns its lifecycle, and reuses `PROFILE_DIR` across restarts. Xvfb supplies the display on a headless Linux host.

The tunnel owns exactly one persistent browser context. Tabs and popups are pages inside that context. Stopping the tunnel closes the browser it owns.

### CDP attach backend

`BROWSER_MODE=cdp` connects to `CDP_ENDPOINT` using Playwright's Chrome DevTools Protocol support. The external service remains the sole owner of the Chromium process and persistent profile. The tunnel does not open `PROFILE_DIR`, launch Chromium, or call `browser.close()` on detach.

`CDP_TARGET` selects an existing tab by case-insensitive URL/title substring. If the external Chromium has zero or multiple tabs, a target is required. An unmatched target fails closed. Only the selected tab and popups opened from that tab are enrolled in the tunnel; unrelated tabs remain outside its `/tabs` and control surface.

At attach time the existing tab's current URL is validated against the destination policy. The tunnel reads the existing viewport instead of imposing startup viewport/locale/timezone settings on the external owner. Existing v0.4.2 redirect, frame-navigation and landing-page guards remain active on the enrolled page.

If the enrolled external tab disappears, CDP mode fails closed rather than creating an arbitrary replacement tab in a browser it does not own.

## Ownership invariant

The durable rule is **one live owner per Chromium profile**, not “one control client per browser.”

- In managed mode, the tunnel is the owner.
- In CDP mode, the external runtime is the owner and the tunnel is a client.
- Multiple CDP clients can technically attach to one externally owned browser, but operators must coordinate actions to avoid competing clicks/navigation.
- No client should open the browser's user-data directory independently while the owner is running.

## Persistent profile

In managed mode, `PROFILE_DIR` contains cookies, local storage, IndexedDB, service-worker state and other browser identity data. Reuse the same directory to preserve authentication across restarts, with exactly one browser process opening it at a time.

In CDP mode, profile location and persistence are external concerns. `PROFILE_DIR` is ignored and never opened by the tunnel.

Treat any persistent browser profile as credential material. Never commit it, copy it into a container image, or expose it through the HTTP API.

## Command serialization

All HTTP requests that touch the browser are converted into commands and executed on the single browser worker thread. This prevents cross-thread Playwright access while still allowing the HTTP server to serve multiple clients concurrently.

The command queue serializes actions inside this tunnel instance. It does not coordinate unrelated external CDP clients; deployment-level coordination is still required when another automation client shares the same browser.

## Authentication flow

The long-lived access token comes from `AUTH_TOKEN` or `TOKEN_FILE`.

For the browser UI:

1. the operator submits the token once to `POST /session`;
2. the server verifies it with a constant-time comparison;
3. the server creates a separate random session identifier;
4. the browser receives that identifier in an `HttpOnly`, `SameSite=Strict` cookie.

The access token is not stored in JavaScript, routine URLs or the session cookie. API clients can use `Authorization: Bearer <token>`.

## Destination policy

Public HTTP and HTTPS destinations are permitted by default. Loopback, private, link-local, reserved and common internal names are blocked.

The policy is applied to:

- explicit top-level navigation;
- redirects;
- page subresources;
- WebSocket connections.

`DENIED_HOSTS` has highest precedence. `ALLOWED_HOSTS` can permit a required internal hostname. `ALLOW_PRIVATE_NETWORK_NAVIGATION=true` disables the private-network restriction globally.

DNS results are cached briefly and explicit navigation forces a fresh lookup. This reduces DNS rebinding exposure while avoiding a lookup for every static asset.

## Screenshots and coordinates

The screenshot endpoint returns the current viewport as PNG. The web UI maps clicks and drags using the PNG element's real `naturalWidth` and `naturalHeight`, not a hard-coded viewport.

Runtime viewport changes update every open page in the browser context. The startup defaults remain `1440×1100`.

## DOM snapshot model

DOM snapshots are an auxiliary structured view; the screenshot remains the authoritative human view.

By default, snapshots omit field values. The authenticated operator can request normal values and, separately, sensitive values such as password, token and OTP inputs. Sensitive disclosure is explicit to avoid accidental copying into logs or agent context.

## Deployment boundaries

The process defaults to `127.0.0.1:19192`. Remote access should use a trusted LAN, VPN, SSH forwarding or a reverse proxy with TLS.

The Docker image binds inside the container to `0.0.0.0:19192`, while the example Compose file publishes it only on host loopback. The systemd example runs under a dedicated user and restricts writable paths to the persistent state directory.
