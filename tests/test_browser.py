from __future__ import annotations

from types import SimpleNamespace

import pytest

from headful_auth_tunnel.browser import CDPBrowserBackend


class FakePage:
    def __init__(self, url, title):
        self.url = url
        self._title = title
        self.closed = False

    def title(self):
        return self._title

    def is_closed(self):
        return self.closed


def make_backend(make_config, target=None):
    return CDPBrowserBackend(
        make_config(
            browser_mode="cdp",
            cdp_endpoint="http://127.0.0.1:9223",
            cdp_target=target,
            profile_dir=None,
        ),
        lambda *_: None,
        lambda *_: None,
        lambda *_: None,
    )


def test_cdp_target_selects_matching_tab(make_config):
    backend = make_backend(make_config, "aliexpress")
    first = FakePage("https://chatgpt.com/", "ChatGPT")
    second = FakePage("https://pt.aliexpress.com/", "AliExpress")
    backend._browser = SimpleNamespace(contexts=[SimpleNamespace(pages=[first, second])])

    _, selected = backend._select_page()

    assert selected is second


def test_cdp_requires_target_when_browser_has_multiple_tabs(make_config):
    backend = make_backend(make_config)
    backend._browser = SimpleNamespace(
        contexts=[
            SimpleNamespace(
                pages=[
                    FakePage("https://a.example/", "A"),
                    FakePage("https://b.example/", "B"),
                ]
            )
        ]
    )

    with pytest.raises(RuntimeError, match="CDP_TARGET"):
        backend._select_page()


def test_cdp_target_must_match(make_config):
    backend = make_backend(make_config, "missing")
    backend._browser = SimpleNamespace(
        contexts=[SimpleNamespace(pages=[FakePage("https://example.com/", "Example")])]
    )

    with pytest.raises(RuntimeError, match="did not match"):
        backend._select_page()
