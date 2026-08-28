from __future__ import annotations

import http.client
import json
import threading
import time
import types
from urllib.parse import urlencode

import pytest

from headful_auth_tunnel.security import NavigationDecision
from headful_auth_tunnel.server import (
    BrowserSession,
    RequestError,
    SessionStore,
    TunnelHTTPServer,
    make_handler,
)


class FakeController:
    def call(self, method, timeout=65, **kwargs):
        if method == "health":
            return {"status": "ok", "browser": True, "tabs": 1}
        if method == "meta":
            return {
                "url": "https://example.com",
                "viewport": {"width": 1440, "height": 1100},
            }
        if method == "tabs":
            return {"tabs": []}
        if method == "page_snapshot":
            return {"title": "Example", "elements": []}
        if method == "screenshot":
            return b"png"
        return {"ok": True, "method": method, **kwargs}


def start_server(config):
    server = TunnelHTTPServer(
        ("127.0.0.1", 0),
        make_handler(config, FakeController(), SessionStore()),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def request(server, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read()
    result_headers = dict(response.getheaders())
    connection.close()
    return response.status, result_headers, payload


def test_login_uses_http_only_cookie_and_no_query_token(make_config):
    config = make_config()
    server, thread = start_server(config)
    try:
        status, headers, body = request(server, "GET", f"/?token={config.auth_token}")
        assert status == 200
        assert b"Access token" in body
        assert "Set-Cookie" not in headers

        encoded = urlencode({"token": config.auth_token})
        status, headers, _ = request(
            server,
            "POST",
            "/session",
            encoded,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status == 303
        cookie = headers["Set-Cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie
        assert config.auth_token not in cookie

        cookie_pair = cookie.split(";", 1)[0]
        status, _, payload = request(server, "GET", "/meta", headers={"Cookie": cookie_pair})
        assert status == 200
        assert json.loads(payload)["viewport"] == {
            "width": 1440,
            "height": 1100,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_forwarded_https_marks_session_cookie_secure(make_config):
    config = make_config(trust_forwarded_proto=True)
    server, thread = start_server(config)
    try:
        encoded = urlencode({"token": config.auth_token})
        status, headers, _ = request(
            server,
            "POST",
            "/session",
            encoded,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Forwarded-Proto": "https",
            },
        )
        assert status == 303
        assert "Secure" in headers["Set-Cookie"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_bearer_auth_and_security_headers(make_config):
    config = make_config()
    server, thread = start_server(config)
    try:
        status, headers, payload = request(
            server,
            "GET",
            "/meta",
            headers={"Authorization": f"Bearer {config.auth_token}"},
        )
        assert status == 200
        assert json.loads(payload)["url"] == "https://example.com"
        assert headers["Cache-Control"].startswith("no-store")
        assert headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_body_limit_returns_413(make_config):
    config = make_config(max_request_bytes=16)
    server, thread = start_server(config)
    try:
        status, _, payload = request(
            server,
            "POST",
            "/navigate",
            body=b"x" * 32,
            headers={
                "Authorization": f"Bearer {config.auth_token}",
                "Content-Type": "application/json",
            },
        )
        assert status == 413
        assert json.loads(payload)["error"] == "Request body is too large"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_session_store_expiry():
    store = SessionStore(ttl_seconds=1)
    token = store.create()
    assert store.valid(token)
    store._sessions[token] = time.time() - 1
    assert not store.valid(token)


def test_viewport_bounds_follow_runtime_resolution(make_config):
    session = BrowserSession(make_config(screen_width=3840, screen_height=2160))
    assert session._point(3839, 2159) == (3839, 2159)


class SnapshotPage:
    def __init__(self):
        self.closed = False
        self.arguments = None
        self.url = "https://example.com"
        self.goto_calls = []
        self.frames = []

    def is_closed(self):
        return self.closed

    def goto(self, url, **kwargs):
        self.goto_calls.append(url)
        self.url = url

    def evaluate(self, script, arguments):
        self.arguments = arguments
        return {"arguments": arguments}


class SnapshotContext:
    def __init__(self, page):
        self.pages = [page]


def test_snapshot_can_explicitly_include_sensitive_values(make_config):
    # _check_final_url re-validates the landed URL; allow example.com
    # explicitly so the guard short-circuits without DNS (netless sandboxes).
    session = BrowserSession(make_config(allowed_hosts=("example.com",)))
    page = SnapshotPage()
    session.context = SnapshotContext(page)
    session.page = page

    result = session.page_snapshot(
        include_values=True,
        include_sensitive_values=True,
    )

    assert result["arguments"]["includeValues"] is True
    assert result["arguments"]["includeSensitiveValues"] is True


def test_browser_metadata_declares_headful_persistent_single_instance(make_config):
    session = BrowserSession(make_config())
    page = SnapshotPage()
    page.url = "https://example.com"
    page.title = lambda: "Example"
    session.context = SnapshotContext(page)
    session.page = page

    first = session.meta()
    second = session.meta()

    assert first["browser_mode"] == "headful"
    assert first["persistent_profile"] is True
    assert first["browser_instance_id"] == second["browser_instance_id"]


class LifecyclePage:
    def __init__(self, *, closed=False, url="about:blank"):
        self.closed = closed
        self.url = url
        self.viewport = None
        self.goto_calls = []
        self.frames = []
        self.handlers = {}

    def on(self, event, callback):
        self.handlers[event] = callback

    def close(self):
        self.closed = True

    def is_closed(self):
        return self.closed

    def set_viewport_size(self, viewport):
        if self.closed:
            raise RuntimeError("Page is closed")
        self.viewport = viewport

    def goto(self, url, wait_until=None, timeout=None):
        if self.closed:
            raise RuntimeError("Page is closed")
        self.goto_calls.append({"url": url, "wait_until": wait_until, "timeout": timeout})
        self.url = url

    def title(self):
        return ""


class LifecycleContext:
    def __init__(self, pages=None):
        self.pages = list(pages or [])

    def new_cdp_session(self, page):
        return types.SimpleNamespace(send=lambda *args, **kwargs: None, on=lambda *args: None)

    def new_page(self):
        page = LifecyclePage()
        self.pages.append(page)
        return page


def _allow_base(url, refresh=False, **_kwargs):
    return NavigationDecision(True, "allowed", url)


def test_on_page_rejects_closed_incoming_page(make_config):
    session = BrowserSession(make_config())
    live = LifecyclePage(url="https://example.com/app")
    closed_popup = LifecyclePage(closed=True, url="about:blank")
    session.context = LifecycleContext([live, closed_popup])
    session.page = None

    session._on_page(closed_popup)

    assert session.page is None
    assert closed_popup.viewport is None


def test_on_page_does_not_install_delayed_closed_popup_over_invalid_current(make_config):
    session = BrowserSession(make_config())
    dead_current = LifecyclePage(closed=True, url="https://example.com/old")
    live = LifecyclePage(url="https://example.com/keep")
    closed_popup = LifecyclePage(closed=True, url="about:blank")
    session.context = LifecycleContext([dead_current, live, closed_popup])
    session.page = dead_current

    session._on_page(closed_popup)

    assert session.page is dead_current
    assert session._current_page() is live


def test_on_page_does_not_retarget_live_current_tab(make_config):
    session = BrowserSession(make_config())
    current = LifecyclePage(url="https://example.com/app")
    popup = LifecyclePage(url="https://example.com/popup")
    session.context = LifecycleContext([current, popup])
    session.page = current

    session._on_page(popup)

    assert session.page is current
    assert popup.viewport == session.viewport


def test_on_page_adopts_live_page_when_current_is_gone(make_config):
    session = BrowserSession(make_config())
    incoming = LifecyclePage(url="https://example.com/fresh")
    session.context = LifecycleContext([incoming])
    session.page = LifecyclePage(closed=True)

    session._on_page(incoming)

    assert session.page is incoming
    assert incoming.viewport == session.viewport


def test_current_page_recovers_zero_tabs_at_configured_base_url(make_config):
    session = BrowserSession(make_config(base_url="https://example.com/login"))
    session.policy.validate = _allow_base
    closed = LifecyclePage(closed=True)
    session.context = LifecycleContext([closed])
    session.page = closed

    recovered = session._current_page()

    assert recovered is not closed
    assert recovered.closed is False
    assert session.page is recovered
    assert recovered.goto_calls == [
        {
            "url": "https://example.com/login",
            "wait_until": "domcontentloaded",
            "timeout": session.config.navigation_timeout_ms,
        }
    ]
    assert recovered.url == "https://example.com/login"
    assert recovered.viewport == session.viewport


def test_current_page_uses_normalized_recovery_url(make_config):
    session = BrowserSession(make_config(base_url="https://example.com"))
    session.policy.validate = lambda url, refresh=False, **_kwargs: NavigationDecision(
        True, "allowed", "https://example.com/"
    )
    session.context = LifecycleContext([])
    session.page = None

    recovered = session._current_page()

    assert recovered.goto_calls[0]["url"] == "https://example.com/"


class FakePage:
    def __init__(self, url="", *, navigate_on_click=None):
        self.url = url
        self.goto_calls = []
        self.frames = []
        self.navigate_on_click = navigate_on_click
        self.mouse = types.SimpleNamespace(click=self._click)
        self.closed = False

    def is_closed(self):
        return self.closed

    def goto(self, url, **kwargs):
        self.goto_calls.append(url)
        self.url = url

    def _click(self, x, y):
        if self.navigate_on_click is not None:
            self.url = self.navigate_on_click


class _ClosableSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _UnreadableUrlPage(FakePage):
    @property
    def url(self):
        raise RuntimeError("url unavailable")

    @url.setter
    def url(self, value):
        self._url = value


class _Frame:
    def __init__(self, page, url):
        self.page = page
        self.url = url


class _UnreadableFrame:
    def __init__(self, page):
        self.page = page

    @property
    def url(self):
        raise RuntimeError("frame url unavailable")


class _RouteRequest:
    def __init__(self, url):
        self.url = url


class _Route:
    def __init__(self):
        self.aborts = []
        self.continued = 0

    def abort(self, reason):
        self.aborts.append(reason)

    def continue_(self):
        self.continued += 1


class _CDP:
    def __init__(self):
        self.commands = []

    def send(self, method, params):
        self.commands.append((method, params))


def _redirect_event(target, *, status=302):
    return {
        "requestId": "request-1",
        "responseStatusCode": status,
        "responseHeaders": [{"name": "Location", "value": target}],
        "request": {"url": "http://127.0.0.1:9999/start"},
    }


def test_direct_route_allows_valid_request(make_config):
    session = BrowserSession(make_config(allow_private_network_navigation=True))
    route = _Route()

    session._route_request(route, _RouteRequest("http://127.0.0.1:9999/start"))

    assert route.continued == 1
    assert route.aborts == []


def test_direct_route_blocks_denied_request(make_config):
    session = BrowserSession(
        make_config(allow_private_network_navigation=True, denied_hosts=("localhost",))
    )
    route = _Route()

    session._route_request(route, _RouteRequest("http://localhost:9999/blocked"))

    assert route.continued == 0
    assert route.aborts == ["blockedbyclient"]


def test_redirect_response_blocks_denied_target_before_follow(make_config):
    session = BrowserSession(
        make_config(allow_private_network_navigation=True, denied_hosts=("localhost",))
    )
    cdp = _CDP()

    session._on_redirect_response_paused(
        cdp,
        _redirect_event("http://localhost:9999/blocked"),
    )

    assert cdp.commands == [
        (
            "Fetch.failRequest",
            {"requestId": "request-1", "errorReason": "BlockedByClient"},
        )
    ]


def test_redirect_response_uses_shared_dns_budget(make_config):
    session = BrowserSession(make_config(allow_private_network_navigation=True))
    session._frame_dns_max_events = 0
    cdp = _CDP()

    session._on_redirect_response_paused(
        cdp,
        _redirect_event("http://127.0.0.1:9999/next"),
    )

    assert cdp.commands == [
        (
            "Fetch.failRequest",
            {"requestId": "request-1", "errorReason": "BlockedByClient"},
        )
    ]


def test_redirect_response_continues_allowed_target(make_config):
    session = BrowserSession(make_config(allow_private_network_navigation=True))
    cdp = _CDP()

    session._on_redirect_response_paused(
        cdp,
        _redirect_event("http://127.0.0.1:9999/next"),
    )

    assert cdp.commands == [("Fetch.continueResponse", {"requestId": "request-1"})]


def test_non_redirect_response_continues_without_dns_budget(make_config):
    session = BrowserSession(make_config(allow_private_network_navigation=True))
    session._frame_dns_max_events = 0
    cdp = _CDP()

    session._on_redirect_response_paused(
        cdp,
        _redirect_event("", status=200),
    )

    assert cdp.commands == [("Fetch.continueResponse", {"requestId": "request-1"})]


def test_startup_final_url_unreadable_fails_closed(make_config):
    session = BrowserSession(make_config())
    session.page = _UnreadableUrlPage()
    session.session = _ClosableSession()

    with pytest.raises(RuntimeError, match="could not be determined"):
        session._check_startup_final_url()

    assert session.session.closed is True


def test_subframe_landing_is_validated_and_quarantined(make_config):
    session = BrowserSession(make_config())
    page = FakePage(url="https://ok.test/")
    frame = _Frame(page, "https://blocked.test/frame")
    calls = []

    class Policy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            calls.append((url, allow_non_network, refresh))
            return NavigationDecision(False, "denied", url)

    session.policy = Policy()
    session._on_frame_navigated(frame)

    assert calls == [("https://blocked.test/frame", True, True)]
    assert page.goto_calls == ["about:blank"]


def test_unreadable_frame_url_is_quarantined(make_config):
    session = BrowserSession(make_config())
    page = FakePage(url="https://ok.test/")

    session._on_frame_navigated(_UnreadableFrame(page))

    assert page.goto_calls == ["about:blank"]


def test_frame_landing_forces_fresh_dns_every_time(make_config):
    session = BrowserSession(make_config())
    page = FakePage(url="https://ok.test/")
    frame = _Frame(page, "https://same.test/frame")
    refreshes = []

    class Policy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            refreshes.append(refresh)
            return NavigationDecision(True, "ok", url)

    session.policy = Policy()
    session._on_frame_navigated(frame)
    session._on_frame_navigated(frame)

    assert refreshes == [True, True]


def test_read_boundary_rejects_blocked_subframe(make_config):
    session = BrowserSession(make_config())
    page = FakePage(url="https://ok.test/")
    page.frames = [_Frame(page, "https://blocked.test/frame")]

    class Policy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            if "blocked.test" in url:
                return NavigationDecision(False, "denied", url)
            return NavigationDecision(True, "ok", url)

    session.policy = Policy()
    with pytest.raises(RequestError, match="Frame blocked"):
        session._check_final_url(page)
    assert page.goto_calls == ["about:blank"]


def test_frame_dns_budget_fails_closed(make_config):
    session = BrowserSession(make_config())
    session._frame_dns_max_events = 2
    page = FakePage(url="https://ok.test/")
    frame = _Frame(page, "https://same.test/frame")
    calls = []

    class Policy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            calls.append((url, refresh))
            return NavigationDecision(True, "ok", url)

    session.policy = Policy()
    session._on_frame_navigated(frame)
    session._on_frame_navigated(frame)
    session._on_frame_navigated(frame)

    assert len(calls) == 2
    assert page.goto_calls == ["about:blank"]


def test_click_checks_landing_before_browser_action(make_config):
    session = BrowserSession(make_config())
    page = FakePage(url="https://blocked.test/")
    page.frames = []
    session.page = page
    session.context = types.SimpleNamespace(pages=[page])
    clicked = []
    page.mouse = types.SimpleNamespace(click=lambda x, y: clicked.append((x, y)))

    class Policy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            return NavigationDecision(False, "denied", url)

    session.policy = Policy()
    with pytest.raises(RequestError, match="Redirected to blocked host"):
        session.click(1, 1)
    assert clicked == []
    assert page.goto_calls == ["about:blank"]


def test_read_frame_sweep_uses_shared_dns_budget(make_config):
    session = BrowserSession(make_config())
    session._frame_dns_max_events = 1
    page = FakePage(url="https://ok.test/")
    page.frames = [_Frame(page, "https://frame.test/")]

    class Policy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            return NavigationDecision(True, "ok", url)

    session.policy = Policy()
    with pytest.raises(RequestError, match="DNS validation budget exceeded"):
        session._check_final_url(page)
    assert page.goto_calls == ["about:blank"]


def test_quarantine_latch_avoids_recursive_frame_handler(make_config):
    session = BrowserSession(make_config())
    session._frame_dns_max_events = 0

    class RecursivePage(FakePage):
        def goto(self, url, **kwargs):
            self.goto_calls.append(url)
            session._on_frame_navigated(_Frame(self, url))

    page = RecursivePage(url="https://ok.test/")
    session._on_frame_navigated(_Frame(page, "https://ok.test/"))
    assert page.goto_calls == ["about:blank"]


def test_final_url_check_refreshes_policy_every_landing(make_config):
    session = BrowserSession(make_config())
    recorded = []

    class RecordingPolicy:
        def validate(self, url, *, allow_non_network=False, refresh=False):
            recorded.append(
                {
                    "url": url,
                    "allow_non_network": allow_non_network,
                    "refresh": refresh,
                }
            )
            return NavigationDecision(True, "ok", url)

    session.policy = RecordingPolicy()
    fake_page = types.SimpleNamespace(url="https://ok.test/", frames=[])

    result = session._check_final_url(fake_page)

    assert recorded[0]["refresh"] is True
    assert result == "https://ok.test/"


def test_final_url_check_quarantines_blocked_page(make_config):
    session = BrowserSession(make_config(denied_hosts=("blocked.test",)))
    fake_page = FakePage(url="https://blocked.test/x")

    with pytest.raises(RequestError) as exc:
        session._check_final_url(fake_page)

    assert exc.value.status == 403
    assert fake_page.goto_calls == ["about:blank"]


def test_browser_action_click_revalidates_final_url(make_config):
    session = BrowserSession(make_config(denied_hosts=("blocked.test",)))
    fake_page = FakePage(
        url="https://ok.test/",
        navigate_on_click="https://blocked.test/landed",
    )
    session.context = types.SimpleNamespace(pages=[fake_page])
    session.page = fake_page

    with pytest.raises(RequestError) as exc:
        session.click(100, 100)

    assert exc.value.status == 403
    assert fake_page.goto_calls == ["about:blank"]
