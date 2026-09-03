from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from playwright.sync_api import sync_playwright
from scrapling.fetchers import StealthySession

from .config import Config

LOGGER = logging.getLogger("headful_auth_tunnel")


@dataclass
class BrowserHandle:
    context: Any
    page: Any
    backend_name: str
    owns_browser: bool
    persistent_profile: bool | None


class ManagedBrowserBackend:
    """Launch and own the Chromium process used by the tunnel."""

    backend_name = "managed"
    owns_browser = True
    persistent_profile = True

    def __init__(self, config: Config, route_request, route_websocket, on_page):
        self.config = config
        self._route_request = route_request
        self._route_websocket = route_websocket
        self._on_page = on_page
        self.session = None
        self.context = None

    def start(self) -> BrowserHandle:
        if self.config.profile_dir is None:
            raise RuntimeError("PROFILE_DIR is required in managed browser mode")

        viewport = {"width": self.config.screen_width, "height": self.config.screen_height}
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
                "viewport": viewport.copy(),
                "screen": viewport.copy(),
                "device_scale_factor": 1,
            },
        )
        self.session.start()
        self.context = self.session.context
        self.context.route("**/*", self._route_request)
        self.context.route_web_socket("**/*", self._route_websocket)
        self.context.on("page", self._on_page)

        pages = [page for page in self.context.pages if not page.is_closed()]
        page = pages[0] if pages else self.context.new_page()
        return BrowserHandle(
            context=self.context,
            page=page,
            backend_name=self.backend_name,
            owns_browser=self.owns_browser,
            persistent_profile=self.persistent_profile,
        )

    def pages(self) -> list[Any]:
        if self.context is None:
            return []
        return [page for page in self.context.pages if not page.is_closed()]

    def close(self) -> None:
        if self.session is None:
            return
        try:
            self.session.close()
        except Exception:
            LOGGER.exception("Failed to close managed browser session")


class CDPBrowserBackend:
    """Attach to an externally owned Chromium without owning lifecycle/profile."""

    backend_name = "cdp"
    owns_browser = False
    persistent_profile = None

    def __init__(self, config: Config, route_request, route_websocket, on_page):
        self.config = config
        self._route_request = route_request
        self._route_websocket = route_websocket
        self._on_page = on_page
        self._playwright = None
        self._browser = None
        self.context = None
        self._attached_pages: list[Any] = []

    def start(self) -> BrowserHandle:
        if not self.config.cdp_endpoint:
            raise RuntimeError("CDP_ENDPOINT is required in cdp browser mode")

        self._playwright = sync_playwright().start()
        try:
            self._browser = self._playwright.chromium.connect_over_cdp(
                self.config.cdp_endpoint,
                timeout=self.config.navigation_timeout_ms,
            )
            context, page = self._select_page()
            self.context = context
            self._attach_page(page)
        except BaseException:
            self.close()
            raise

        return BrowserHandle(
            context=context,
            page=page,
            backend_name=self.backend_name,
            owns_browser=self.owns_browser,
            persistent_profile=self.persistent_profile,
        )

    def _select_page(self):
        candidates = []
        for context in self._browser.contexts:
            for page in context.pages:
                if not page.is_closed():
                    candidates.append((context, page))

        target = (self.config.cdp_target or "").strip().lower()
        if target:
            matches = [
                (context, page) for context, page in candidates if self._matches(page, target)
            ]
            if not matches:
                raise RuntimeError(
                    f"CDP_TARGET did not match any open tab: {self.config.cdp_target}"
                )
            return matches[-1]

        if len(candidates) != 1:
            raise RuntimeError(
                "CDP_TARGET is required when the external browser has zero or multiple open tabs"
            )
        return candidates[0]

    @staticmethod
    def _matches(page, target: str) -> bool:
        if target in (page.url or "").lower():
            return True
        try:
            return target in page.title().lower()
        except Exception:
            return False

    def _attach_page(self, page) -> None:
        if page in self._attached_pages or page.is_closed():
            return
        self._attached_pages.append(page)
        page.route("**/*", self._route_request)
        if hasattr(page, "route_web_socket"):
            page.route_web_socket("**/*", self._route_websocket)
        page.on("popup", self._on_popup)

    def _on_popup(self, page) -> None:
        self._attach_page(page)
        self._on_page(page)

    def pages(self) -> list[Any]:
        self._attached_pages = [page for page in self._attached_pages if not page.is_closed()]
        return list(self._attached_pages)

    def close(self) -> None:
        # Deliberately do not call browser.close(): Chromium belongs to another service.
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                LOGGER.exception("Failed to detach Playwright from external Chromium")
            finally:
                self._playwright = None
                self._browser = None
                self.context = None
                self._attached_pages.clear()


def make_browser_backend(
    config: Config,
    route_request: Callable,
    route_websocket: Callable,
    on_page: Callable,
):
    if config.browser_mode == "cdp":
        return CDPBrowserBackend(config, route_request, route_websocket, on_page)
    return ManagedBrowserBackend(config, route_request, route_websocket, on_page)
