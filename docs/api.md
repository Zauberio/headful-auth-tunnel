# HTTP API

## Authentication

Browser sessions use the signed per-browser/device cookie returned by `POST /session`. The cookie survives tunnel restarts and lasts 30 days by default (`SESSION_TTL_SECONDS=2592000`). Rotating the master access token invalidates outstanding browser sessions. Programmatic clients may send:

```http
Authorization: Bearer <access-token>
```

`GET /health`, `GET /`, `GET /app.css` and `POST /session` are available before authentication. All browser-control and state endpoints require authentication.

All JSON request bodies must be objects. The default maximum body size is 1 MiB.

## Error format

```json
{"error":"Human-readable error"}
```

Common status codes:

- `400` invalid input;
- `401` missing or invalid authentication;
- `403` destination policy rejection;
- `404` unknown endpoint or tab;
- `409` invalid state, such as closing the last tab;
- `413` request body too large;
- `500` unexpected browser/server failure;
- `503` degraded health or a full command queue.

## Session endpoints

### `POST /session`

Accepts form data or JSON:

```json
{"token":"access-token"}
```

Returns `303 See Other` and sets the signed `HttpOnly`, `SameSite=Strict` per-browser/device session cookie. The access token itself is not stored in the cookie.

### `POST /logout`

Clears the current browser session cookie and redirects to `/`. Rotating the master access token is the global revocation mechanism for all outstanding signed browser sessions.

## State and screenshots

### `GET /health`

Returns:

```json
{"status":"ok"}
```

With `EXPOSE_HEALTH_DETAILS=true`, browser and tab counts are included.

When the service is launched through `scripts/start.sh`, the launcher injects an ephemeral per-start readiness nonce. In that case `/health` also includes `"readiness_nonce":"..."`; the helper accepts startup only when the spawned PID remains alive and the exact nonce is echoed. The field is absent for normal/manual launches and is not an authentication credential.

### `GET /meta`

Returns the active URL/title, viewport, locale, timezone, browser presentation mode, backend/owner metadata, persistent-profile flag and tunnel browser-session identifier. `browser_backend` is `managed` or `cdp`; `browser_owner` is `tunnel` or `external`. In CDP mode `persistent_profile` is `null` because profile persistence belongs to the external owner.

### `GET /screenshot`

Returns a PNG of the current viewport.

### `GET /tabs`

Returns pages enrolled in this tunnel session. In managed mode this is the tunnel-owned context. In CDP mode it is the selected target tab plus popups opened from that tab; unrelated tabs in the external Chromium are intentionally omitted.


```json
{
  "tabs": [
    {"id":"7f...","title":"Example","url":"https://example.com","active":true}
  ]
}
```

### `GET /page`

Returns a DOM snapshot without field values.

### `POST /page`

```json
{
  "include_values": true,
  "include_sensitive_values": false
}
```

Set `include_sensitive_values` only when the authenticated operator explicitly needs password, token or OTP values.

## Navigation

### `POST /navigate`

```json
{"url":"https://example.com/login"}
```

The URL must pass the destination policy.

### `POST /reload`

Empty JSON object.

### `POST /history/back`

Empty JSON object.

### `POST /history/forward`

Empty JSON object.

## Viewport and pointer

### `POST /viewport`

```json
{"width":1920,"height":1200}
```

Supported range: width 320–7680, height 240–4320.

### `POST /click`

```json
{"x":400,"y":300}
```

### `POST /drag`

```json
{
  "from":{"x":300,"y":500},
  "to":{"x":900,"y":500},
  "duration_ms":500
}
```

## Keyboard

### `POST /type`

```json
{"text":"user@example.com"}
```

### `POST /key`

```json
{"key":"Control+A"}
```

Key names use Playwright keyboard syntax.

## Tabs

### `POST /tabs/focus`

```json
{"id":"7f..."}
```

### `POST /tabs/close`

```json
{"id":"7f..."}
```

The final remaining tab cannot be closed.

## Selector helpers

### `POST /dom/fill`

```json
{"selector":"input[name=email]","value":"user@example.com"}
```

### `POST /dom/click`

```json
{"selector":"button[type=submit]"}
```

### `POST /dom/press`

```json
{"selector":"input[name=otp]","key":"Enter"}
```

### `POST /dom/select`

```json
{"selector":"select[name=country]","value":"PT"}
```

These helpers act on the first matching element and use a 10-second operation timeout.

## `POST /pointer/down`

Begin an interactive left-button pointer gesture at screenshot coordinates. Used by explicit **Drag mode** in the web UI.

```json
{"x": 640, "y": 420}
```

## `POST /pointer/move`

Move an already-active interactive pointer gesture. Returns `409` when no pointer gesture is active.

```json
{"x": 720, "y": 420}
```

## `POST /pointer/up`

Move to the final coordinates and release the active pointer gesture.

```json
{"x": 800, "y": 420}
```

## `POST /pointer/cancel`

Release an active pointer gesture without further movement.

The web UI keeps **Drag: Off** by default so ordinary buttons, menus and dropdowns continue to use `POST /click`; enable Drag mode only for continuous human pointer gestures.
