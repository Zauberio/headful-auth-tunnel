from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import secrets
import ssl
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

from scrapling.fetchers import StealthySession

from .config import Config
from .security import NavigationPolicy, bearer_token, token_from_cookie
from .ui import APP_CSS, APP_HTML, APP_JS, LOGIN_HTML

LOGGER = logging.getLogger("headful_auth_tunnel")


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class _Command:
    method: str
    kwargs: dict[str, Any]
    future: Future


class BrowserSession:
    def __init__(self, config: Config):
        self.config = config
        self.policy = NavigationPolicy(config)
        self.session = None
        self.context = None
        self.page = None
        self.viewport = {"width": config.screen_width, "height": config.screen_height}
        self.instance_id = secrets.token_hex(8)
        self.started_at = time.time()
        self._frame_dns_window_started = time.monotonic()
        self._frame_dns_events = 0
        self._frame_dns_window_seconds = 5.0
        self._frame_dns_max_events = 32
        self._read_frame_limit = 64
        self._quarantining_pages: set[int] = set()

    def start(self) -> None:
        decision = self.policy.validate(self.config.base_url, refresh=True)
        if not decision.allowed:
            raise RuntimeError(f"BASE_URL blocked: {decision.reason}")

        self.session = StealthySession(
            headless=False,
            user_data_dir=str(self.config.profile_dir),
            executable_path=(
                str(self.config.browser_executable_path)
                if self.config.browser_executable_path
                else None
            ),
            locale=self.config.locale,
            timezone_id=self.config.timezone_id,
            timeout=self.config.navigation_timeout_ms,
            solve_cloudflare=False,
            allow_webgl=True,
            hide_canvas=False,
            block_webrtc=True,
            google_search=False,
            network_idle=False,
            load_dom=False,
            max_pages=20,
            additional_args={
                "viewport": self.viewport.copy(),
                "screen": self.viewport.copy(),
                "device_scale_factor": 1,
            },
        )
        self.session.start()
        self.context = self.session.context
        self.context.route("**/*", self._route_request)
        self.context.route_web_socket("**/*", self._route_websocket)
        self.context.on("page", self._on_page)

        pages = [page for page in self.context.pages if not page.is_closed()]
        self.page = pages[0] if pages else self.context.new_page()
        # Attach browser-triggered landing guards to each existing page.
        for p in pages:
            self._attach_redirect_response_guard(p)
            try:
                p.on("framenavigated", self._on_frame_navigated)
            except Exception:
                LOGGER.exception("Failed to attach frame navigation handler to existing page")
        self._attach_redirect_response_guard(self.page)
        self.page.set_viewport_size(self.viewport)
        self.page.goto(
            decision.normalized_url or self.config.base_url,
            wait_until="domcontentloaded",
            timeout=self.config.navigation_timeout_ms,
        )
        # A 302 from BASE_URL to a denied host is followed internally by
        # Chromium (never routed) - re-validate where we actually landed.
        self._check_startup_final_url()

    def _check_startup_final_url(self) -> str:
        final_url = self._final_url(self.page)
        if not final_url:
            self.session.close()
            raise RuntimeError("BASE_URL final URL could not be determined")
        decision = self.policy.validate(final_url, refresh=True)
        if not decision.allowed:
            self.session.close()
            raise RuntimeError(f"BASE_URL redirected to blocked host: {decision.reason}")
        return decision.normalized_url or final_url

    def close(self) -> None:
        if self.session is not None:
            try:
                self.session.close()
            except Exception:
                LOGGER.exception("Failed to close browser session")

    def _route_request(self, route, request) -> None:
        decision = self.policy.validate(request.url, allow_non_network=True)
        if decision.allowed:
            route.continue_()
            return
        LOGGER.warning("Blocked browser request to %s: %s", request.url, decision.reason)
        route.abort("blockedbyclient")

    def _attach_redirect_response_guard(self, page) -> None:
        if getattr(page, "_hat_redirect_guard", None) is not None:
            return
        try:
            cdp = self.context.new_cdp_session(page)
            cdp.send(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]},
            )
            cdp.on(
                "Fetch.requestPaused",
                lambda event, session=cdp: self._on_redirect_response_paused(session, event),
            )
        except Exception as exc:
            raise RuntimeError("Failed to attach redirect response guard") from exc
        page._hat_redirect_guard = cdp

    def _on_redirect_response_paused(self, cdp, event: dict[str, Any]) -> None:
        request_id = event.get("requestId")
        if not request_id:
            return
        try:
            status = int(event.get("responseStatusCode") or 0)
            if status in {301, 302, 303, 307, 308}:
                headers = {
                    str(header.get("name", "")).lower(): str(header.get("value", ""))
                    for header in event.get("responseHeaders", [])
                }
                location = headers.get("location", "")
                if location:
                    source = str(event.get("request", {}).get("url", ""))
                    target = urljoin(source, location)
                    if not self._consume_frame_dns_budget():
                        LOGGER.warning(
                            "Blocked browser redirect to %s: DNS validation budget exceeded",
                            target,
                        )
                        cdp.send(
                            "Fetch.failRequest",
                            {"requestId": request_id, "errorReason": "BlockedByClient"},
                        )
                        return
                    decision = self.policy.validate(target, refresh=True)
                    if not decision.allowed:
                        LOGGER.warning(
                            "Blocked browser redirect to %s: %s",
                            target,
                            decision.reason,
                        )
                        cdp.send(
                            "Fetch.failRequest",
                            {"requestId": request_id, "errorReason": "BlockedByClient"},
                        )
                        return
            cdp.send("Fetch.continueResponse", {"requestId": request_id})
        except Exception:
            LOGGER.exception("Redirect response validation failed")
            with contextlib.suppress(Exception):
                cdp.send(
                    "Fetch.failRequest",
                    {"requestId": request_id, "errorReason": "BlockedByClient"},
                )

    def _route_websocket(self, websocket_route) -> None:
        decision = self.policy.validate_websocket(websocket_route.url)
        if decision.allowed:
            websocket_route.connect_to_server()
        else:
            LOGGER.warning(
                "Blocked browser WebSocket to %s: %s",
                websocket_route.url,
                decision.reason,
            )
            websocket_route.close(code=1008, reason="Destination blocked")

    def _on_page(self, page) -> None:
        # Only adopt the new page as "current" if we have no current page at
        # all (first tab). window.open / target=_blank popups must NOT
        # silently retarget /navigate, /click, /type, /page - the operator
        # should pick a tab explicitly via /tabs/focus. A delayed "page"
        # event for a just-closed popup must not be installed either: that
        # leaves a dead pointer and the next command silently falls back to
        # another tab.
        if page.is_closed():
            return
        try:
            page.set_viewport_size(self.viewport)
        except Exception:
            LOGGER.exception("Failed to size new page")
        # Cover browser-triggered redirects and navigations on every new page.
        try:
            self._attach_redirect_response_guard(page)
            page.on("framenavigated", self._on_frame_navigated)
        except Exception:
            LOGGER.exception("Failed to attach browser landing guards")
            with contextlib.suppress(Exception):
                page.close()
            return
        if self.page is None or self.page.is_closed() or self.page not in self._pages():
            self.page = page

    def _consume_frame_dns_budget(self) -> bool:
        now = time.monotonic()
        if now - self._frame_dns_window_started >= self._frame_dns_window_seconds:
            self._frame_dns_window_started = now
            self._frame_dns_events = 0
        if self._frame_dns_events >= self._frame_dns_max_events:
            return False
        self._frame_dns_events += 1
        return True

    def _quarantine_page(self, page, log_message: str) -> None:
        key = id(page)
        if key in self._quarantining_pages:
            return
        self._quarantining_pages.add(key)
        try:
            page.goto("about:blank")
        except Exception:
            LOGGER.exception(log_message)
        finally:
            self._quarantining_pages.discard(key)

    def _consume_dns_or_block(self, page, reason: str) -> None:
        if self._consume_frame_dns_budget():
            return
        LOGGER.warning("Blocked browser access: DNS validation budget exceeded")
        self._quarantine_page(page, "Failed to quarantine page after DNS budget exhaustion")
        raise RequestError(403, reason)

    def _on_frame_navigated(self, frame) -> None:
        """Fail closed for browser-triggered main-frame and sub-frame landings."""
        try:
            page = frame.page if hasattr(frame, "page") and frame.page else self._current_page()
        except Exception:
            page = self._current_page()

        if id(page) in self._quarantining_pages:
            return

        try:
            url = frame.url or ""
        except Exception:
            url = ""

        if not url:
            LOGGER.warning("Blocked frame navigation: final URL could not be determined")
            self._quarantine_page(page, "Failed to quarantine frame with unreadable URL")
            return

        if not self._consume_frame_dns_budget():
            LOGGER.warning("Blocked frame navigation: DNS validation budget exceeded")
            self._quarantine_page(
                page,
                "Failed to quarantine page after DNS budget exhaustion",
            )
            return

        try:
            decision = self.policy.validate(
                url,
                allow_non_network=True,
                refresh=True,
            )
        except Exception:
            LOGGER.exception("Frame navigation validation failed")
            self._quarantine_page(page, "Failed to quarantine frame after validation error")
            return

        if decision.allowed:
            return

        LOGGER.warning("Blocked frame navigation to %s: %s", url, decision.reason)
        self._quarantine_page(page, "Failed to quarantine frame-blocked page")

    def _pages(self) -> list[Any]:
        if self.context is None:
            return []
        return [page for page in self.context.pages if not page.is_closed()]

    def _current_page(self):
        pages = self._pages()
        if not pages:
            # The last tab was closed (API close_tab has a 409 guard, but a
            # human closing the tab or window.close() in page JS bypasses it).
            # Recover by opening a fresh page instead of bricking every
            # control endpoint with "No browser page is available" until
            # restart.
            try:
                fresh = self.context.new_page()
                fresh.set_viewport_size(self.viewport)
            except Exception:
                raise RuntimeError("No browser page is available") from None
            self.page = fresh
            try:
                decision = self.policy.validate(self.config.base_url, refresh=True)
                if decision.allowed:
                    fresh.goto(
                        decision.normalized_url or self.config.base_url,
                        wait_until="domcontentloaded",
                        timeout=self.config.navigation_timeout_ms,
                    )
            except Exception:
                LOGGER.exception("Failed to open BASE_URL on recovered page")
            return fresh
        if self.page not in pages:
            self.page = pages[-1]
        return self.page

    def _find_page(self, page_id: str):
        for page in self._pages():
            if self._page_id(page) == page_id:
                return page
        raise RequestError(404, "Tab not found")

    _page_id_counter = 0

    def _page_id(self, page) -> str:
        # id(page) is a CPython heap address: after GC, a newly opened tab
        # can receive the id of an already-closed one (empirically 19
        # collisions in 120 open/close cycles), so a stale client-held id
        # silently aliases a DIFFERENT live tab. Use a monotonic counter.
        stored = getattr(page, "_hat_page_id", None)
        if stored is None:
            type(self)._page_id_counter += 1
            stored = format(self._page_id_counter, "x")
            with contextlib.suppress(Exception):
                page._hat_page_id = stored  # type: ignore[attr-defined]
        return stored

    def health(self) -> dict[str, Any]:
        pages = self._pages()
        return {"status": "ok", "browser": bool(pages), "tabs": len(pages)}

    def meta(self) -> dict[str, Any]:
        page = self._current_page()
        try:
            title = page.title()
        except Exception:
            title = ""
        return {
            "url": page.url,
            "title": title,
            "viewport": self.viewport.copy(),
            "screenshot_interval_ms": self.config.screenshot_interval_ms,
            "locale": self.config.locale,
            "timezone_id": self.config.timezone_id,
            "private_network_navigation": self.config.allow_private_network_navigation,
            "browser_mode": "headful",
            "persistent_profile": True,
            "browser_instance_id": self.instance_id,
            "browser_started_at": self.started_at,
        }

    def tabs(self) -> dict[str, Any]:
        current = self._current_page()
        items = []
        for page in self._pages():
            try:
                title = page.title()
            except Exception:
                title = ""
            items.append(
                {
                    "id": self._page_id(page),
                    "title": title,
                    "url": page.url,
                    "active": page is current,
                }
            )
        return {"tabs": items}

    def focus_tab(self, id: str) -> dict[str, Any]:
        page = self._find_page(id)
        page.bring_to_front()
        self.page = page
        return self.meta()

    def close_tab(self, id: str) -> dict[str, Any]:
        pages = self._pages()
        if len(pages) <= 1:
            raise RequestError(409, "The last tab cannot be closed")
        page = self._find_page(id)
        page.close()
        remaining = self._pages()
        self.page = remaining[-1]
        self.page.bring_to_front()
        return self.tabs()

    def screenshot(self) -> bytes:
        page = self._current_page()
        self._check_final_url(page)
        return page.screenshot(type="png", full_page=False)

    def _final_url(self, page) -> str:
        try:
            return page.url or ""
        except Exception:
            return ""

    def _check_final_url(self, page) -> str:
        """Re-validate the URL a page actually landed on.

        Server-side 302/307 redirects are followed internally by Chromium
        and never pass through page.route, so the navigation policy only
        ever saw the ORIGINAL url. A redirect from an allowed origin to a
        DENIED_HOSTS entry (open redirect, SSO bounce) would otherwise load
        denied content fully readable through /page and /screenshot.
        """
        url = self._final_url(page)
        if not url:
            self._quarantine_page(page, "Failed to quarantine page with unreadable URL")
            raise RequestError(403, "Blocked: could not determine final URL")
        self._consume_dns_or_block(page, "Blocked: DNS validation budget exceeded")
        decision = self.policy.validate(url, allow_non_network=True, refresh=True)
        if not decision.allowed:
            self._quarantine_page(page, "Failed to quarantine blocked page")
            raise RequestError(403, f"Redirected to blocked host: {decision.reason}")

        try:
            frames = list(page.frames)
        except Exception:
            self._quarantine_page(
                page,
                "Failed to quarantine page with unreadable frame inventory",
            )
            raise RequestError(403, "Blocked: could not inspect page frames") from None
        if len(frames) > self._read_frame_limit:
            self._quarantine_page(page, "Failed to quarantine page with excessive frame count")
            raise RequestError(403, "Blocked: page has too many frames")

        for frame in frames:
            try:
                frame_url = frame.url or ""
            except Exception:
                frame_url = ""
            if not frame_url:
                self._quarantine_page(
                    page,
                    "Failed to quarantine page with unreadable frame URL",
                )
                raise RequestError(403, "Blocked: could not determine frame URL")
            self._consume_dns_or_block(page, "Blocked: DNS validation budget exceeded")
            frame_decision = self.policy.validate(
                frame_url,
                allow_non_network=True,
                refresh=True,
            )
            if not frame_decision.allowed:
                self._quarantine_page(page, "Failed to quarantine page with blocked frame")
                raise RequestError(403, f"Frame blocked: {frame_decision.reason}")

        return decision.normalized_url or url

    def navigate(self, url: str) -> dict[str, Any]:
        decision = self.policy.validate(url, refresh=True)
        if not decision.allowed:
            raise RequestError(403, decision.reason)
        page = self._current_page()
        page.goto(
            decision.normalized_url or url,
            wait_until="domcontentloaded",
            timeout=self.config.navigation_timeout_ms,
        )
        self._check_final_url(page)
        return self.meta()

    def reload(self) -> dict[str, Any]:
        page = self._current_page()
        page.reload(wait_until="domcontentloaded", timeout=self.config.navigation_timeout_ms)
        self._check_final_url(page)
        return self.meta()

    def history_back(self) -> dict[str, Any]:
        page = self._current_page()
        page.go_back(wait_until="domcontentloaded", timeout=self.config.navigation_timeout_ms)
        self._check_final_url(page)
        return self.meta()

    def history_forward(self) -> dict[str, Any]:
        page = self._current_page()
        page.go_forward(wait_until="domcontentloaded", timeout=self.config.navigation_timeout_ms)
        self._check_final_url(page)
        return self.meta()

    def set_viewport(self, width: int, height: int) -> dict[str, Any]:
        if not 320 <= width <= 7680 or not 240 <= height <= 4320:
            raise RequestError(400, "Viewport must be between 320×240 and 7680×4320")
        self.viewport = {"width": width, "height": height}
        for page in self._pages():
            page.set_viewport_size(self.viewport)
        return self.meta()

    def _point(self, x: int, y: int) -> tuple[int, int]:
        width, height = self.viewport["width"], self.viewport["height"]
        if not 0 <= x < width or not 0 <= y < height:
            raise RequestError(400, f"Point must be inside {width}×{height}")
        return x, y

    def click(self, x: int, y: int) -> dict[str, bool]:
        x, y = self._point(x, y)
        page = self._current_page()
        self._check_final_url(page)
        page.mouse.click(x, y)
        self._check_final_url(page)
        return {"ok": True}

    def drag(
        self,
        from_x: int,
        from_y: int,
        to_x: int,
        to_y: int,
        duration_ms: int = 500,
    ) -> dict[str, bool]:
        from_x, from_y = self._point(from_x, from_y)
        to_x, to_y = self._point(to_x, to_y)
        duration_ms = max(50, min(duration_ms, 5000))
        steps = max(5, min(100, duration_ms // 20))
        page = self._current_page()
        self._check_final_url(page)
        mouse = page.mouse
        mouse.move(from_x, from_y)
        mouse.down()
        try:
            mouse.move(to_x, to_y, steps=steps)
        finally:
            mouse.up()
        self._check_final_url(page)
        return {"ok": True}

    def type_text(self, text: str) -> dict[str, bool]:
        if len(text) > self.config.max_type_text_chars:
            raise RequestError(400, "Text is too long")
        page = self._current_page()
        self._check_final_url(page)
        page.keyboard.type(text)
        self._check_final_url(page)
        return {"ok": True}

    def press_key(self, key: str) -> dict[str, bool]:
        key = key.strip()
        if not key or len(key) > 100:
            raise RequestError(400, "Key must contain between 1 and 100 characters")
        page = self._current_page()
        self._check_final_url(page)
        page.keyboard.press(key)
        self._check_final_url(page)
        return {"ok": True}

    def dom_fill(self, selector: str, value: str) -> dict[str, bool]:
        selector = self._validate_selector(selector)
        page = self._current_page()
        self._check_final_url(page)
        page.locator(selector).first.fill(value, timeout=10000)
        self._check_final_url(page)
        return {"ok": True}

    def dom_click(self, selector: str) -> dict[str, bool]:
        selector = self._validate_selector(selector)
        page = self._current_page()
        self._check_final_url(page)
        page.locator(selector).first.click(timeout=10000)
        self._check_final_url(page)
        return {"ok": True}

    def dom_press(self, selector: str, key: str) -> dict[str, bool]:
        selector = self._validate_selector(selector)
        if not key or len(key) > 100:
            raise RequestError(400, "Invalid key")
        page = self._current_page()
        self._check_final_url(page)
        page.locator(selector).first.press(key, timeout=10000)
        self._check_final_url(page)
        return {"ok": True}

    def dom_select(self, selector: str, value: str) -> dict[str, Any]:
        selector = self._validate_selector(selector)
        page = self._current_page()
        self._check_final_url(page)
        selected = page.locator(selector).first.select_option(value=value, timeout=10000)
        self._check_final_url(page)
        return {"ok": True, "selected": selected}

    @staticmethod
    def _validate_selector(selector: str) -> str:
        selector = selector.strip()
        if not selector or len(selector) > 1000:
            raise RequestError(400, "Selector must contain between 1 and 1000 characters")
        return selector

    def page_snapshot(
        self,
        include_values: bool = False,
        include_sensitive_values: bool = False,
    ) -> dict[str, Any]:
        page = self._current_page()
        self._check_final_url(page)
        return page.evaluate(
            """({elementLimit, textLimit, includeValues, includeSensitiveValues}) => {
              const sensitive = new RegExp(
                'pass(word)?|secret|token|auth|otp|one.?time|cvv|cvc|credit.?card',
                'i'
              );
              const bodyText = document.body ? (document.body.innerText || '') : '';
              const nodes = Array.from(document.querySelectorAll(
                'input, textarea, select, button, a, [contenteditable="true"]'
              )).slice(0, elementLimit);
              const elements = nodes.map((el) => {
                const tag = el.tagName.toLowerCase();
                const type = (el.getAttribute('type') || '').toLowerCase();
                const identity = [el.id, el.getAttribute('name'), el.getAttribute('autocomplete')]
                  .filter(Boolean).join(' ');
                const isSensitive = (
                  type === 'password' || type === 'hidden' || sensitive.test(identity)
                );
                const item = {
                  tag,
                  type,
                  id: el.id || null,
                  name: el.getAttribute('name'),
                  role: el.getAttribute('role'),
                  aria_label: el.getAttribute('aria-label'),
                  placeholder: el.getAttribute('placeholder'),
                  text: (el.innerText || el.textContent || '').trim().slice(0, 300),
                  href: tag === 'a' ? el.href : null,
                  disabled: Boolean(el.disabled),
                  editable: (
                    tag === 'input' || tag === 'textarea' ||
                    tag === 'select' || el.isContentEditable
                  ),
                  sensitive: isSensitive
                };
                if (
                  includeValues &&
                  (!isSensitive || includeSensitiveValues) &&
                  ['input', 'textarea', 'select'].includes(tag)
                ) {
                  item.value = String(el.value || '').slice(0, 2000);
                }
                return item;
              });
              return {
                title: document.title,
                url: location.href,
                text: bodyText.slice(0, textLimit),
                text_truncated: bodyText.length > textLimit,
                elements
              };
            }""",
            {
                "elementLimit": self.config.max_dom_elements,
                "textLimit": self.config.max_dom_text_chars,
                "includeValues": bool(include_values),
                "includeSensitiveValues": bool(include_sensitive_values),
            },
        )


class BrowserController:
    def __init__(self, config: Config):
        self.config = config
        self._queue: queue.Queue[_Command | None] = queue.Queue(maxsize=128)
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="browser-worker", daemon=True)
        self._startup_error: BaseException | None = None

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=90):
            raise RuntimeError("Browser worker did not become ready")
        if self._startup_error is not None:
            raise RuntimeError("Browser worker failed to start") from self._startup_error

    def _run(self) -> None:
        session = BrowserSession(self.config)
        try:
            session.start()
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            return
        self._ready.set()

        while True:
            command = self._queue.get()
            if command is None:
                break
            try:
                result = getattr(session, command.method)(**command.kwargs)
            except BaseException as exc:
                command.future.set_exception(exc)
            else:
                command.future.set_result(result)
        session.close()

    def call(self, method: str, timeout: float = 65, **kwargs):
        future: Future = Future()
        try:
            self._queue.put(_Command(method, kwargs, future), timeout=2)
        except queue.Full as exc:
            raise RequestError(503, "Browser command queue is full") from exc
        return future.result(timeout=timeout)

    def close(self) -> None:
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            return
        self._thread.join(timeout=10)


class SessionStore:
    def __init__(self, ttl_seconds: int = 43200):
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._purge(now)
            if len(self._sessions) >= 128:
                oldest = min(self._sessions, key=self._sessions.get)
                self._sessions.pop(oldest, None)
            self._sessions[token] = now + self.ttl_seconds
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        now = time.time()
        with self._lock:
            self._purge(now)
            expires = self._sessions.get(token)
            return expires is not None and expires > now

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def _purge(self, now: float) -> None:
        expired = [token for token, expires in self._sessions.items() if expires <= now]
        for token in expired:
            self._sessions.pop(token, None)


def make_handler(config: Config, controller: BrowserController, sessions: SessionStore):
    readiness_nonce = os.environ.get("HEADFUL_READINESS_NONCE") or None

    class Handler(BaseHTTPRequestHandler):
        server_version = "HeadfulAuthTunnel/0.4.0"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(config.socket_timeout_seconds)

        def log_message(self, fmt: str, *args) -> None:
            path = urlsplit(self.path).path
            LOGGER.info("%s %s %s", self.client_address[0], self.command, path)

        def _headers(
            self,
            content_type: str,
            length: int,
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' blob: data:; script-src 'self'; "
                "style-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'",
            )
            if config.tls_enabled:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            if extra:
                for name, value in extra.items():
                    self.send_header(name, value)

        def _send_bytes(
            self,
            status: int,
            payload: bytes,
            content_type: str,
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self._headers(content_type, len(payload), extra)
            self.end_headers()
            self.wfile.write(payload)

        def _send_text(
            self,
            status: int,
            text: str,
            content_type: str = "text/plain; charset=utf-8",
            extra: dict[str, str] | None = None,
        ) -> None:
            self._send_bytes(status, text.encode("utf-8"), content_type, extra)

        def _send_json(self, status: int, payload: Any) -> None:
            raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_bytes(status, raw, "application/json; charset=utf-8")

        def _redirect(self, location: str, extra: dict[str, str] | None = None) -> None:
            headers = {"Location": location}
            if extra:
                headers.update(extra)
            self._send_bytes(303, b"", "text/plain; charset=utf-8", headers)

        def _read_body(self) -> bytes:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise RequestError(400, "Invalid Content-Length") from exc
            if length < 0:
                raise RequestError(400, "Invalid Content-Length")
            if length > config.max_request_bytes:
                raise RequestError(413, "Request body is too large")
            return self.rfile.read(length)

        def _json_body(self) -> dict[str, Any]:
            raw = self._read_body()
            if not raw:
                return {}
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RequestError(400, "Request body must be valid JSON") from exc
            if not isinstance(payload, dict):
                raise RequestError(400, "JSON body must be an object")
            return payload

        def _cookie_value(self) -> str | None:
            return token_from_cookie(self.headers.get("Cookie"), config.session_cookie_name)

        def _authenticated(self) -> bool:
            supplied = bearer_token(self.headers.get("Authorization"))
            if supplied and compare_digest(supplied, config.auth_token):
                return True
            return sessions.valid(self._cookie_value())

        def _require_auth(self) -> bool:
            if self._authenticated():
                return True
            self._send_json(401, {"error": "Authentication required"})
            return False

        def _session_cookie(self, session_id: str, *, clear: bool = False) -> str:
            parts = [
                f"{config.session_cookie_name}={session_id}",
                "Path=/",
                "HttpOnly",
                "SameSite=Strict",
            ]
            if clear:
                parts.extend(["Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"])
            else:
                parts.append("Max-Age=43200")
            forwarded_https = (
                config.trust_forwarded_proto
                and self.headers.get("X-Forwarded-Proto", "").strip().lower() == "https"
            )
            if config.tls_enabled or forwarded_https:
                parts.append("Secure")
            return "; ".join(parts)

        def _handle_error(self, exc: BaseException) -> None:
            if isinstance(exc, RequestError):
                self._send_json(exc.status, {"error": exc.message})
                return
            if isinstance(exc, (ValueError, TypeError)):
                self._send_json(400, {"error": "Invalid request parameters"})
                return
            LOGGER.exception("Request failed")
            self._send_json(500, {"error": "Internal server error"})

        def do_GET(self) -> None:
            try:
                self._do_GET()
            except BaseException as exc:
                self._handle_error(exc)

        def _do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path

            if path == "/health":
                try:
                    health = controller.call("health", timeout=5)
                except Exception:
                    health = {"status": "degraded", "browser": False}
                if not config.expose_health_details:
                    health = {"status": health["status"]}
                if readiness_nonce:
                    health["nonce"] = readiness_nonce
                self._send_json(200 if health["status"] == "ok" else 503, health)
                return

            if path == "/app.css":
                self._send_text(200, APP_CSS, "text/css; charset=utf-8")
                return

            if path == "/" and config.allow_query_token:
                query_token = parse_qs(parsed.query).get("token", [None])[0]
                if query_token and compare_digest(query_token, config.auth_token):
                    session_id = sessions.create()
                    self._redirect("/", {"Set-Cookie": self._session_cookie(session_id)})
                    return

            if path == "/":
                if self._authenticated():
                    self._send_text(200, APP_HTML, "text/html; charset=utf-8")
                else:
                    self._send_text(200, LOGIN_HTML, "text/html; charset=utf-8")
                return

            if not self._require_auth():
                return

            if path == "/app.js":
                self._send_text(200, APP_JS, "application/javascript; charset=utf-8")
            elif path == "/meta":
                self._send_json(200, controller.call("meta"))
            elif path == "/tabs":
                self._send_json(200, controller.call("tabs"))
            elif path == "/screenshot":
                self._send_bytes(200, controller.call("screenshot"), "image/png")
            elif path == "/page":
                self._send_json(
                    200,
                    controller.call(
                        "page_snapshot",
                        include_values=False,
                        include_sensitive_values=False,
                    ),
                )
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            try:
                self._do_POST()
            except BaseException as exc:
                self._handle_error(exc)

        def _do_POST(self) -> None:
            path = urlsplit(self.path).path

            if path == "/session":
                raw = self._read_body()
                content_type = self.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    try:
                        body = json.loads(raw or b"{}")
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        raise RequestError(400, "Request body must be valid JSON") from exc
                    supplied = body.get("token", "") if isinstance(body, dict) else ""
                else:
                    supplied = parse_qs(raw.decode("utf-8", errors="strict")).get("token", [""])[0]
                if not isinstance(supplied, str) or not compare_digest(supplied, config.auth_token):
                    self._send_json(401, {"error": "Invalid token"})
                    return
                session_id = sessions.create()
                self._redirect("/", {"Set-Cookie": self._session_cookie(session_id)})
                return

            if path == "/logout":
                session_id = self._cookie_value()
                sessions.revoke(session_id)
                self._redirect(
                    "/",
                    {"Set-Cookie": self._session_cookie("", clear=True)},
                )
                return

            if not self._require_auth():
                return

            body = self._json_body()
            if path == "/navigate":
                result = controller.call("navigate", url=str(body.get("url", "")))
            elif path == "/reload":
                result = controller.call("reload")
            elif path == "/history/back":
                result = controller.call("history_back")
            elif path == "/history/forward":
                result = controller.call("history_forward")
            elif path == "/viewport":
                result = controller.call(
                    "set_viewport",
                    width=int(body.get("width", 0)),
                    height=int(body.get("height", 0)),
                )
            elif path == "/click":
                result = controller.call(
                    "click",
                    x=int(body.get("x", -1)),
                    y=int(body.get("y", -1)),
                )
            elif path == "/drag":
                start = body.get("from") or {}
                end = body.get("to") or {}
                if not isinstance(start, dict) or not isinstance(end, dict):
                    raise RequestError(400, "Drag points must be objects")
                result = controller.call(
                    "drag",
                    from_x=int(start.get("x", -1)),
                    from_y=int(start.get("y", -1)),
                    to_x=int(end.get("x", -1)),
                    to_y=int(end.get("y", -1)),
                    duration_ms=int(body.get("duration_ms", 500)),
                )
            elif path == "/type":
                result = controller.call("type_text", text=str(body.get("text", "")))
            elif path == "/key":
                result = controller.call("press_key", key=str(body.get("key", "")))
            elif path == "/tabs/focus":
                result = controller.call("focus_tab", id=str(body.get("id", "")))
            elif path == "/tabs/close":
                result = controller.call("close_tab", id=str(body.get("id", "")))
            elif path == "/dom/fill":
                result = controller.call(
                    "dom_fill",
                    selector=str(body.get("selector", "")),
                    value=str(body.get("value", "")),
                )
            elif path == "/dom/click":
                result = controller.call(
                    "dom_click",
                    selector=str(body.get("selector", "")),
                )
            elif path == "/dom/press":
                result = controller.call(
                    "dom_press",
                    selector=str(body.get("selector", "")),
                    key=str(body.get("key", "")),
                )
            elif path == "/dom/select":
                result = controller.call(
                    "dom_select",
                    selector=str(body.get("selector", "")),
                    value=str(body.get("value", "")),
                )
            elif path == "/page":
                result = controller.call(
                    "page_snapshot",
                    include_values=bool(body.get("include_values", False)),
                    include_sensitive_values=bool(body.get("include_sensitive_values", False)),
                )
            else:
                self._send_json(404, {"error": "Not found"})
                return
            self._send_json(200, result)

    return Handler


class TunnelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        config = Config.from_env()
    except ValueError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc

    controller = BrowserController(config)
    controller.start()
    sessions = SessionStore()
    server = TunnelHTTPServer(
        (config.bind_host, config.port),
        make_handler(config, controller, sessions),
    )

    if config.tls_enabled:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(config.tls_cert), str(config.tls_key))
        server.socket = context.wrap_socket(server.socket, server_side=True)

    scheme = "https" if config.tls_enabled else "http"
    LOGGER.info(
        "Headful Auth Tunnel listening on %s://%s:%s",
        scheme,
        config.bind_host,
        config.port,
    )
    if config.token_file:
        LOGGER.info("Authentication token file: %s", config.token_file)
    else:
        LOGGER.info("Authentication token supplied through AUTH_TOKEN")

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        controller.close()


if __name__ == "__main__":
    main()
